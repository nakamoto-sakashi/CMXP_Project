#!/bin/bash

set -e

# 1. Download and install the Cloudflare Tunnel client
echo "[INIT] Downloading cloudflared..."
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared
chmod +x cloudflared
echo "[INIT] cloudflared downloaded."

# 2. Start the Cloudflare Tunnel in the background
#    Redirect its output to a log file so we can view it.
echo "[INIT] Starting Cloudflare Tunnel and logging to cloudflare.log..."
./cloudflared tunnel --no-autoupdate --protocol ws run --token $CLOUDFLARE_TOKEN > cloudflare.log 2>&1 &

# 3. Wait a bit longer for the tunnel to initialize and write to the log
echo "[INIT] Waiting 8 seconds for tunnel to connect..."
sleep 8

# 4. Display the log file to find our public URL
echo "--- Displaying Cloudflare Tunnel logs ---"
cat cloudflare.log
echo "-----------------------------------------"

# 5. Start the Stratum server in the foreground
echo "[INIT] Starting CMXP Stratum Server on port 10000..."
python stratum_server.py