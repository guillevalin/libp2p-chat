use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures::{prelude::*, select, FutureExt};
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify,
    identity::Keypair,
    kad::{store::MemoryStore, Config as KademliaConfig, Behaviour as Kademlia},
    mdns,
    multiaddr::Multiaddr,
    noise,
    ping,
    relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, SwarmBuilder,
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

const BOOTNODES: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
];

#[derive(Debug, Parser)]
#[command(name = "libp2p-chat")]
#[command(about = "A libp2p-based chat application with relay and hole punching support")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run as a regular peer (client mode)
    Peer {
        /// Multiaddress to listen on (optional)
        #[arg(short, long)]
        listen: Option<Multiaddr>,
        /// Relay address to connect through
        #[arg(short, long)]
        relay: Option<Multiaddr>,
        /// Bootstrap nodes to connect to
        #[arg(short, long)]
        bootstrap: Vec<Multiaddr>,
        /// Chat room to join
        #[arg(short = 'c', long, default_value = "libp2p-chat")]
        room: String,
    },
    /// Run as a relay server
    Relay {
        /// Port to listen on
        #[arg(short, long, default_value = "4001")]
        port: u16,
        /// Use IPv6
        #[arg(long)]
        ipv6: bool,
        /// Secret key seed for deterministic peer ID
        #[arg(long, default_value = "0")]
        secret_key_seed: u8,
    },
}

#[derive(NetworkBehaviour)]
struct SimpleBehaviour {
    identify: identify::Behaviour,
    kademlia: Kademlia<MemoryStore>,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("libp2p_chat=info".parse()?))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Peer {
            listen,
            relay,
            bootstrap,
            room,
        } => run_peer(listen, relay, bootstrap, room).await,
        Commands::Relay {
            port,
            ipv6,
            secret_key_seed,
        } => run_relay(port, ipv6, secret_key_seed).await,
    }
}

async fn run_peer(
    listen_addr: Option<Multiaddr>,
    relay_addr: Option<Multiaddr>,
    bootstrap_addrs: Vec<Multiaddr>,
    room: String,
) -> Result<()> {
    info!("Starting libp2p chat peer...");

    // Generate or use a deterministic key
    let local_key = Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local peer id: {}", local_peer_id);

    // Build swarm using the new SwarmBuilder API
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|keypair| {
            // Create a simple behavior without relay client for now
            let local_peer_id = PeerId::from(keypair.public());
            
            // Initialize basic behaviors
            let identify = identify::Behaviour::new(identify::Config::new(
                "/libp2p-chat/1.0".to_string(),
                keypair.public(),
            ));

            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                local_peer_id,
            ).expect("Failed to create mDNS behaviour");

            let ping = ping::Behaviour::new(ping::Config::new());

            // Initialize gossipsub for chat
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(ValidationMode::Permissive) // Allow messages from any peer
                .build()
                .expect("Valid gossipsub config");
            
            let gossipsub = gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(keypair.clone()),
                gossipsub_config,
            ).expect("Correct configuration");

            // Initialize Kademlia
            let store = MemoryStore::new(local_peer_id);
            let kademlia = Kademlia::with_config(local_peer_id, store, KademliaConfig::default());

            // Create simple behavior struct
            SimpleBehaviour {
                identify,
                mdns,
                ping,
                gossipsub,
                kademlia,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Subscribe to chat room
    let topic = IdentTopic::new(room.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    info!("Subscribed to chat room: {}", room);

    // Listen on specified address or default
    let listen_address = listen_addr.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
    swarm.listen_on(listen_address)?;

    // Connect to relay if specified
    if let Some(relay_addr) = relay_addr {
        info!("Connecting to relay: {}", relay_addr);
        swarm.dial(relay_addr)?;
    }

    // Connect to bootstrap nodes
    for addr in bootstrap_addrs {
        info!("Connecting to bootstrap node: {}", addr);
        swarm.dial(addr)?;
    }

    // Start Kademlia bootstrap
    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
        warn!("Failed to start Kademlia bootstrap: {}", e);
    }

    // Handle stdin for user input
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line_buffer = String::new();

    loop {
        select! {
            result = reader.read_line(&mut line_buffer).fuse() => {
                match result {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let line = line_buffer.trim();
                        if !line.is_empty() {
                            let message = format!("{}: {}", local_peer_id, line);
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), message.as_bytes()) {
                                error!("Failed to publish message: {}", e);
                            } else {
                                info!("Sent: {}", line);
                            }
                        }
                        line_buffer.clear();
                    },
                    Err(e) => {
                        error!("Error reading from stdin: {}", e);
                        break;
                    }
                }
            },
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on: {}", address);
                    },
                    SwarmEvent::Behaviour(event) => {
                        handle_behaviour_event(event, &room, &mut swarm).await;
                    },
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!("Connected to peer: {} via {}", peer_id, endpoint.get_remote_address());
                    },
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        info!("Disconnected from peer: {} (cause: {:?})", peer_id, cause);
                    },
                    SwarmEvent::IncomingConnection { .. } => {},
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        warn!("Outgoing connection error to {:?}: {}", peer_id, error);
                    },
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        warn!("Incoming connection error: {}", error);
                    },
                    other => {
                        debug!("Other swarm event: {:?}", other);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_behaviour_event(event: SimpleBehaviourEvent, _room: &str, swarm: &mut libp2p::Swarm<SimpleBehaviour>) {
    match event {
        SimpleBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source: _,
            message_id: _,
            message,
        }) => {
            let msg = String::from_utf8_lossy(&message.data);
            info!("Received: {}", msg);
        },
        SimpleBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
            for (peer_id, multiaddr) in list {
                info!("Discovered peer via mDNS: {} at {}", peer_id, multiaddr);
                // Explicitly dial the peer to establish a stable connection
                if let Err(e) = swarm.dial(multiaddr.clone()) {
                    warn!("Failed to dial discovered peer {}: {:?}", peer_id, e);
                } else {
                    debug!("Dialing discovered peer: {}", peer_id);
                }
            }
        },
        SimpleBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
            for (peer_id, multiaddr) in list {
                debug!("mDNS peer expired: {} at {}", peer_id, multiaddr);
            }
        },
        SimpleBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
            info!("Identified peer: {} with protocol version: {}", peer_id, info.protocol_version);
        },
        SimpleBehaviourEvent::Identify(identify::Event::Sent { peer_id, .. }) => {
            debug!("Sent identify info to: {}", peer_id);
        },
        SimpleBehaviourEvent::Kademlia(kad_event) => {
            debug!("Kademlia event: {:?}", kad_event);
        },
        SimpleBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        }) => {
            debug!("Ping to {} succeeded with RTT: {:?}", peer, rtt);
        },
        SimpleBehaviourEvent::Ping(ping::Event {
            peer,
            result: Err(failure),
            ..
        }) => {
            warn!("Ping to {} failed: {:?}", peer, failure);
        },
        SimpleBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
            info!("Peer {} subscribed to topic: {}", peer_id, topic);
        },
        SimpleBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
            info!("Peer {} unsubscribed from topic: {}", peer_id, topic);
        },
        SimpleBehaviourEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported { peer_id }) => {
            warn!("Peer {} does not support gossipsub", peer_id);
        },
        _ => {
            debug!("Other behaviour event: {:?}", event);
        }
    }
}

async fn run_relay(port: u16, use_ipv6: bool, secret_key_seed: u8) -> Result<()> {
    info!("Starting libp2p relay server on port {}...", port);

    // Generate deterministic key for consistent peer ID
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;
    let local_key = Keypair::ed25519_from_bytes(bytes)
        .context("Failed to create keypair from seed")?;
    
    let local_peer_id = PeerId::from(local_key.public());
    info!("Relay peer ID: {}", local_peer_id);

    // Build swarm for relay
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| relay::Behaviour::new(local_peer_id, Default::default()))?
        .build();

    // Listen on specified addresses
    let listen_addr_v4 = format!("/ip4/0.0.0.0/tcp/{}", port).parse::<Multiaddr>()?;
    swarm.listen_on(listen_addr_v4)?;

    if use_ipv6 {
        let listen_addr_v6 = format!("/ip6/::/tcp/{}", port).parse::<Multiaddr>()?;
        swarm.listen_on(listen_addr_v6)?;
    }

    info!("Relay server started. Listening for connections...");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Relay listening on: {}", address);
            },
            SwarmEvent::Behaviour(relay::Event::ReservationReqAccepted {
                src_peer_id,
                renewed,
            }) => {
                info!(
                    "Relay reservation {} for peer: {}",
                    if renewed { "renewed" } else { "accepted" },
                    src_peer_id
                );
            },
            SwarmEvent::Behaviour(relay::Event::ReservationReqDenied { src_peer_id }) => {
                warn!("Relay reservation denied for peer: {}", src_peer_id);
            },
            SwarmEvent::Behaviour(relay::Event::CircuitReqDenied { src_peer_id, dst_peer_id }) => {
                warn!("Circuit request denied from {} to {}", src_peer_id, dst_peer_id);
            },
            SwarmEvent::Behaviour(relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id }) => {
                info!("Circuit established between {} and {}", src_peer_id, dst_peer_id);
            },
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                info!("Relay connected to peer: {} via {}", peer_id, endpoint.get_remote_address());
            },
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("Relay disconnected from peer: {} (cause: {:?})", peer_id, cause);
            },
            SwarmEvent::IncomingConnectionError { error, .. } => {
                warn!("Relay incoming connection error: {}", error);
            },
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!("Relay outgoing connection error to {:?}: {}", peer_id, error);
            },
            other => {
                debug!("Other relay event: {:?}", other);
            }
        }
    }
} 