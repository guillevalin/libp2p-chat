#!/bin/bash

# libp2p-chat Example Usage Scripts
# Run these in separate terminals to test different scenarios

echo "======================================"
echo "libp2p-chat Example Usage"
echo "======================================"

echo ""
echo "1. Local Network Chat (same network)"
echo "-------------------------------------"
echo "Terminal 1:"
echo "  cargo run -- peer --room 'local-test'"
echo ""
echo "Terminal 2:"
echo "  cargo run -- peer --room 'local-test'"
echo ""

echo "2. Relay Server Setup"
echo "---------------------"
echo "Terminal 1 (Relay Server):"
echo "  cargo run -- relay --port 4001"
echo ""
echo "Note the Peer ID printed by the relay server!"
echo ""

echo "3. Connect via Relay (replace RELAY_PEER_ID)"
echo "--------------------------------------------"
echo "Terminal 2 (Peer A):"
echo "  cargo run -- peer --relay '/ip4/127.0.0.1/tcp/4001/p2p/RELAY_PEER_ID' --room 'relay-test'"
echo ""
echo "Terminal 3 (Peer B):"
echo "  cargo run -- peer --relay '/ip4/127.0.0.1/tcp/4001/p2p/RELAY_PEER_ID' --room 'relay-test'"
echo ""

echo "4. Custom Chat Room"
echo "-------------------"
echo "  cargo run -- peer --room 'my-secret-room'"
echo ""

echo "5. Debug Mode"
echo "-------------"
echo "  RUST_LOG=debug cargo run -- peer --room 'debug-room'"
echo ""

echo "6. Help Commands"
echo "----------------"
echo "  cargo run -- peer --help"
echo "  cargo run -- relay --help"
echo ""

echo "======================================"
echo "Quick Test Commands"
echo "======================================"

read -p "Do you want to start a relay server now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting relay server..."
    cargo run -- relay --port 4001
fi 