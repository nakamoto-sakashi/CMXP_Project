#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# 1. Download and install the Cloudflare Tunnel client
echo "[INIT] Downloading cloudflared..."
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared
chmod +x cloudflared
echo "[INIT] cloudflared downloaded."

# 2. Start the Cloudflare Tunnel in the background
#    It connects to Cloudflare and proxies traffic to our local Stratum port (10000)
#    The tunnel token is read from the $CLOUDFLARE_TOKEN environment variable
echo "[INIT] Starting Cloudflare Tunnel in the background..."
./cloudflared tunnel --no-autoupdate --protocol ws run --token $CLOUDFLARE_TOKEN &

# Give the tunnel a moment to establish the connection
sleep 5 

# 3. Start the Stratum server in the foreground
#    This is the main application process.
echo "[INIT] Starting CMXP Stratum Server on port 10000..."
python stratum_server.py