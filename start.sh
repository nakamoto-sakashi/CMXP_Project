#!/bin/bash

set -e

# 1. Download and install the Cloudflare Tunnel client
echo "[INIT] Downloading cloudflared..."
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared
chmod +x cloudflared
echo "[INIT] cloudflared downloaded."

# 2. Start the tunnel using the simple URL method.
#    This command automatically creates a secure tunnel and generates a public URL.
#    We log the output to a file to capture the URL.
echo "[INIT] Starting Cloudflare Tunnel to expose localhost:10000..."
./cloudflared tunnel --url http://localhost:10000 > cloudflare.log 2>&1 &

# 3. Wait for the tunnel to initialize and generate the URL.
echo "[INIT] Waiting 8 seconds for tunnel URL to be generated..."
sleep 8

# 4. Display the log file. The public URL will be visible here.
echo "--- Displaying Cloudflare Tunnel logs (Your URL is in here!) ---"
cat cloudflare.log
echo "----------------------------------------------------------------"

# 5. Start the Stratum server in the foreground.
#    The tunnel will keep running in the background.
echo "[INIT] Starting CMXP Stratum Server on port 10000..."
python stratum_server.py