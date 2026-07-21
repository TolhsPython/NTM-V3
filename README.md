# Network Traffic Monitor V3

Real-time network traffic visualization on an interactive world map with live connection tracking, geolocation, and system monitoring.

## Features

- Interactive world map with live connection lines and dots
- Real-time bandwidth monitoring (download/upload)
- IP geolocation with city-level accuracy
- Connection details panel (process, service, RTT, state)
- Bandwidth graph with Catmull-Rom spline smoothing
- Per-process bandwidth tracking
- System monitoring (CPU, RAM, swap, disk I/O, temps)
- WiFi signal strength monitoring
- VPN detection (tun/wg/ppp/tailscale)
- Port scan detection and alerts
- LAN device discovery
- Ping monitor with latency/loss/jitter
- DNS query logging
- Data usage summaries (day/week/month)
- Connection event log
- Session recording
- Speedtest integration
- Export to CSV/JSON
- Screenshot capture
- Dark Mode (AMOLED)

## Quick Start

```bash
git clone https://github.com/TolhsPython/NTM-V3.git
cd NTM-V3
bash setup.sh
bash run.sh
```

## Manual Setup

### Install Dependencies

```bash
pip3 install psutil pywebview requests speedtest-cli
sudo dnf install tshark arp-scan 2>/dev/null || sudo apt install tshark arp-scan 2>/dev/null
```

| Package | Purpose |
|---------|---------|
| `psutil` | Process and system monitoring |
| `pywebview` | Native desktop window (GTK backend) |
| `requests` | IP geolocation API calls |
| `speedtest-cli` | Internet speed testing |
| `tshark` | DNS query capture (optional) |
| `arp-scan` | LAN device discovery (optional) |

## Usage

```bash
bash run.sh
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Focus connection filter |
| `Ctrl+E` | Export CSV |
| `Ctrl+S` | Screenshot |
| `Ctrl+,` | Open settings |
| `Esc` | Close panel |

## Platform

Developed and Tested on Fedora/RHEL-based Linux with KDE Plasma (Wayland).
