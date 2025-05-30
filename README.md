# libp2p-chat

A comprehensive peer-to-peer chat application built with rust-libp2p that demonstrates:

- **Peer-to-peer messaging** using GossipSub
- **Relay server functionality** for NAT traversal
- **Hole punching** with DCUTR protocol
- **Peer discovery** via mDNS and Kademlia DHT
- **Circuit relay** support for nodes behind NAT

This project is inspired by examples from the [rust-libp2p repository](https://github.com/libp2p/rust-libp2p/tree/master/examples) and incorporates best practices for building robust peer-to-peer applications.

## Features

### 🖥️ Peer Mode (Client)
- Join chat rooms and send messages
- Auto-discover peers on the local network via mDNS
- Connect through relay servers for NAT traversal
- Support for hole punching to establish direct connections
- Bootstrap with well-known nodes

### 🌐 Relay Server Mode
- Act as a relay to help other peers connect
- Support circuit relay for peers behind NAT
- Configurable port and IPv6 support
- Deterministic peer ID for reliable addressing

### 🔧 Technical Features
- **Transport**: TCP with Noise encryption and Yamux multiplexing
- **Messaging**: GossipSub for efficient message broadcasting
- **Discovery**: mDNS for local discovery, Kademlia for global DHT
- **NAT Traversal**: Relay protocol with DCUTR for hole punching
- **Security**: All connections are encrypted and authenticated

## Installation

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))

### Build from Source
```bash
git clone <repository-url>
cd libp2p-chat
cargo build --release
```

## Usage

### Running a Relay Server

Start a relay server that other peers can use for NAT traversal:

```bash
# Basic relay server on port 4001
cargo run -- relay

# Custom port with IPv6 support
cargo run -- relay --port 8000 --ipv6

# Deterministic peer ID (useful for known relay addresses)
cargo run -- relay --secret-key-seed 42
```

The relay server will print its peer ID and listening addresses. Note these for connecting peers.

### Running a Peer (Client)

Start a peer to join chat rooms and send messages:

```bash
# Basic peer (will auto-discover local peers)
cargo run -- peer

# Connect through a specific relay
cargo run -- peer --relay /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW...

# Join a specific chat room
cargo run -- peer --room "my-secret-chat"

# Connect to specific bootstrap nodes
cargo run -- peer --bootstrap /ip4/10.0.0.1/tcp/4001/p2p/12D3KooW...
```

### Example Scenarios

#### Local Network Chat
```bash
# Terminal 1: Start first peer
cargo run -- peer --room "local-chat"

# Terminal 2: Start second peer (will auto-discover via mDNS)
cargo run -- peer --room "local-chat"
```

#### Cross-Network Chat with Relay
```bash
# Terminal 1: Start relay server
cargo run -- relay --port 4001

# Terminal 2: Start peer A (note the relay peer ID from Terminal 1)
cargo run -- peer --relay /ip4/127.0.0.1/tcp/4001/p2p/12D3KooW... --room "global-chat"

# Terminal 3: Start peer B (from different network)
cargo run -- peer --relay /ip4/YOUR_PUBLIC_IP/tcp/4001/p2p/12D3KooW... --room "global-chat"
```

### Command Reference

#### Peer Mode Options
```
cargo run -- peer [OPTIONS]

Options:
  -l, --listen <LISTEN>        Multiaddress to listen on (optional)
  -r, --relay <RELAY>          Relay address to connect through
  -b, --bootstrap <BOOTSTRAP>  Bootstrap nodes to connect to
  -c, --room <ROOM>           Chat room to join [default: libp2p-chat]
  -h, --help                  Print help
```

#### Relay Mode Options
```
cargo run -- relay [OPTIONS]

Options:
  -p, --port <PORT>                     Port to listen on [default: 4001]
      --ipv6                           Use IPv6
      --secret-key-seed <SECRET_KEY_SEED> Secret key seed for deterministic peer ID [default: 0]
  -h, --help                          Print help
```

## Network Architecture

### Peer Discovery
1. **Local Discovery**: mDNS automatically discovers peers on the same network
2. **Global Discovery**: Kademlia DHT for discovering peers across the internet
3. **Bootstrap Nodes**: Connect to well-known nodes to join the global network

### NAT Traversal
1. **Circuit Relay**: Peers connect through relay servers when direct connection fails
2. **Hole Punching**: DCUTR protocol attempts to establish direct connections
3. **Fallback**: If hole punching fails, communication continues through relay

### Message Flow
```
[Peer A] ---> [GossipSub] ---> [Relay] ---> [GossipSub] ---> [Peer B]
                    |                              |
                    v                              v
              [Local Peers]                [Remote Peers]
```

## Environment Variables

Configure logging and behavior:

```bash
# Enable debug logging
export RUST_LOG=debug
cargo run -- peer

# Enable only libp2p-chat logs
export RUST_LOG=libp2p_chat=info
cargo run -- peer

# Detailed libp2p protocol logs
export RUST_LOG=libp2p=debug,libp2p_chat=info
cargo run -- peer
```

## Troubleshooting

### Common Issues

**Peers can't find each other locally**
- Ensure both peers are in the same chat room (`--room`)
- Check firewall settings allow mDNS traffic
- Verify both peers are on the same network segment

**Can't connect through relay**
- Verify relay server is running and accessible
- Check the relay peer ID is correct
- Ensure firewall allows traffic on relay port

**High bandwidth usage**
- This is expected with GossipSub in large networks
- Consider implementing message filtering for production use

### Debug Mode

Run with detailed logging to troubleshoot:

```bash
RUST_LOG=debug cargo run -- peer --room "debug-room"
```

## Architecture Details

### Network Protocols Used

- **TCP**: Base transport layer
- **Noise**: Encryption and authentication
- **Yamux**: Stream multiplexing
- **GossipSub**: Message broadcasting
- **Kademlia**: Distributed hash table
- **mDNS**: Local service discovery
- **Circuit Relay v2**: NAT traversal
- **DCUTR**: Direct Connection Upgrade through Relay

### Security

- All connections are encrypted with Noise protocol
- Messages are signed to prevent tampering
- Peer identity verification through cryptographic keys
- Protection against eclipse attacks via multiple bootstrap nodes

## Performance Considerations

- **Memory**: Kademlia and GossipSub maintain peer state
- **Bandwidth**: GossipSub floods messages to all subscribers
- **Latency**: Direct connections preferred over relayed connections
- **Scalability**: DHT scales logarithmically with network size

## Contributing

This project demonstrates libp2p concepts and is suitable for educational use. For production applications, consider:

- Implementing proper authentication and authorization
- Adding message persistence and history
- Optimizing GossipSub configuration for your use case
- Adding support for file transfers and media
- Implementing user interfaces beyond CLI

## References

- [rust-libp2p Documentation](https://docs.rs/libp2p/)
- [libp2p Specifications](https://github.com/libp2p/specs)
- [rust-libp2p Examples](https://github.com/libp2p/rust-libp2p/tree/master/examples)
- [Hole Punching Tutorial](https://docs.rs/libp2p/latest/libp2p/tutorials/hole_punching/index.html)

## License

This project is licensed under the MIT License - see the LICENSE file for details. 