#!/bin/bash
echo "=== Network Traffic Monitor V3 - Setup ==="
echo ""

if ! command -v python3 &>/dev/null; then
    echo "Installing Python3..."
    sudo dnf install -y python3 python3-pip 2>/dev/null || sudo apt install -y python3 python3-pip 2>/dev/null
fi

echo "Installing Python packages..."
pip3 install psutil pywebview requests speedtest-cli

echo "Installing system tools..."
sudo dnf install -y tshark arp-scan iw 2>/dev/null || sudo apt install -y tshark arp-scan iw 2>/dev/null

echo ""
echo "=== Setup complete! ==="
echo "Run with: bash run.sh"
