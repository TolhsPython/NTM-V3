#!/usr/bin/env python3
"""Network Traffic Monitor - Global Map Visualization"""

import os
import sys
import json
import re
import csv
import time
import socket
import subprocess
import threading
import logging
from collections import deque, Counter
from datetime import datetime, timedelta

import requests
import psutil
import webview

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class LogCapture:
    def __init__(self):
        self._buffer = []
        self._lock = threading.Lock()
        self._idx = 0

    def write(self, msg):
        if msg and msg.strip():
            with self._lock:
                self._buffer.append({"t": time.time(), "msg": msg.rstrip()})
                if len(self._buffer) > 500:
                    self._buffer = self._buffer[-300:]

    def flush(self):
        pass

    def get(self, since=0):
        with self._lock:
            return [e for e in self._buffer if e["t"] > since]


_log_capture = LogCapture()


class TeeWriter:
    def __init__(self, original, capture):
        self._orig = original
        self._cap = capture

    def write(self, msg):
        self._orig.write(msg)
        self._cap.write(msg)

    def flush(self):
        self._orig.flush()


class LogHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            _log_capture.write(msg)
        except Exception:
            pass


def _install_logging():
    handler = LogHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(name)s: %(message)s'))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)

def _thread_excepthook(args):
    try:
        _log_capture.write(f"[THREAD ERROR] {args.thread.name}: {args.exc_value}")
    except Exception:
        pass

threading.excepthook = _thread_excepthook

def _install_excepthook():
    def hook(exc_type, exc_value, exc_tb):
        import traceback
        try:
            lines = traceback.format_exception(exc_type, exc_value, exc_tb)
            _log_capture.write("[UNCAUGHT] " + "".join(lines).rstrip())
        except Exception:
            pass
    sys.excepthook = hook


CACHE_FILE = os.path.join(BASE_DIR, "geoip_cache.json")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")
DATA_DIR = os.path.join(BASE_DIR, "data")
RECORDINGS_DIR = os.path.join(BASE_DIR, "recordings")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def log(msg):
    _log_capture.write(f"[NETMON] {msg}")

for d in [DATA_DIR, RECORDINGS_DIR, REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)

DEFAULT_SETTINGS = {
    "line_color": "#c678dd",
    "line_width": 2,
    "dot_size": 6,
    "dot_color": "#61afef",
    "home_dot_color": "#98c379",
    "map_theme": "dark",
    "show_labels": False,
    "alert_dl_threshold": 0,
    "alert_ul_threshold": 0,
    "alert_cooldown": 30,
    "notifications": True,
    "record_sessions": False,
    "flow_animation": True,
    "connection_cards": False,
    "service_icons": True,
    "map_clustering": False,
    "trail_effects": False,
    "mini_pie_charts": True,
    "latency_zones": True,
    "rtt_colors": True,
    "bandwidth_thickness": True,
    "bandwidth_arcs": False,
}

PORT_SERVICE_MAP = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    6881: "BitTorrent", 6889: "BitTorrent", 16881: "BitTorrent",
    6667: "IRC", 5222: "XMPP", 5228: "FCM", 5269: "XMPP-S2S",
    5672: "AMQP", 8883: "MQTTS", 9001: "Tor", 9050: "Tor",
    1935: "RTMP", 554: "RTSP", 1900: "SSDP", 5353: "mDNS",
    67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP",
    3478: "STUN", 5349: "STUNS", 10000: "Webmin",
}

SERVICE_PATTERNS = {
    "googlevideo.com": "YouTube",
    "youtube.com": "YouTube",
    "ytimg.com": "YouTube",
    "ggpht.com": "YouTube",
    "discord.com": "Discord",
    "discord.gg": "Discord",
    "discordapp.com": "Discord",
    "discord.media": "Discord",
    "discordapp.net": "Discord",
    "github.com": "GitHub",
    "github.io": "GitHub",
    "githubassets.com": "GitHub",
    "cloudflare.com": "Cloudflare",
    "cdn77.org": "CDN77",
    "akamaized.net": "Akamai",
    "akamaihd.net": "Akamai",
    "amazonaws.com": "AWS",
    "amazon.com": "Amazon",
    "cloudfront.net": "CloudFront",
    "fastly.net": "Fastly",
    "edgekey.net": "Akamai",
    "azure.com": "Azure",
    "microsoft.com": "Microsoft",
    "live.com": "Microsoft",
    "office.com": "Microsoft",
    "office365.com": "Microsoft",
    "windows.com": "Microsoft",
    "google.com": "Google",
    "googleapis.com": "Google",
    "gstatic.com": "Google",
    "g.co": "Google",
    "1e100.net": "Google",
    "googleusercontent.com": "Google",
    "facebook.com": "Facebook",
    "fbcdn.net": "Facebook",
    "instagram.com": "Instagram",
    "cdninstagram.com": "Instagram",
    "whatsapp.com": "WhatsApp",
    "twitter.com": "Twitter",
    "x.com": "Twitter",
    "twimg.com": "Twitter",
    "t.co": "Twitter",
    "reddit.com": "Reddit",
    "redditstatic.com": "Reddit",
    "redditmedia.com": "Reddit",
    "twitch.tv": "Twitch",
    "jtvnw.net": "Twitch",
    "ttvnw.net": "Twitch",
    "netflix.com": "Netflix",
    "nflxvideo.net": "Netflix",
    "nflximg.net": "Netflix",
    "spotify.com": "Spotify",
    "scdn.co": "Spotify",
    "open.spotify.com": "Spotify",
    "steamcontent.com": "Steam",
    "steampowered.com": "Steam",
    "steamstatic.com": "Steam",
    "valve.net": "Steam",
    "ovh.net": "OVH",
    "ip-api.com": "ip-api",
    "scaleway.com": "Scaleway",
    "digitalocean.com": "DigitalOcean",
    "linode.com": "Linode",
    "herokuapp.com": "Heroku",
    "heroku.com": "Heroku",
    "slack.com": "Slack",
    "slack-edge.com": "Slack",
    "zoom.us": "Zoom",
    "telegram.org": "Telegram",
    "t.me": "Telegram",
    "cdn-telegram.org": "Telegram",
    "wikipedia.org": "Wikipedia",
    "wikimedia.org": "Wikipedia",
    "apple.com": "Apple",
    "icloud.com": "Apple",
    "mzstatic.com": "Apple",
    "paypal.com": "PayPal",
    "ebay.com": "eBay",
    "mozilla.org": "Mozilla",
    "firefox.com": "Mozilla",
    "temu.com": "Temu",
    "ajay.app": "Ajay",
    "signal.org": "Signal",
    "whispersystems.org": "Signal",
    "matrix.org": "Matrix",
    "element.io": "Element",
    "proton.me": "Proton",
    "protonmail.com": "Proton",
    "nordvpn.com": "NordVPN",
    "wireguard.com": "WireGuard",
}

ISP_SERVICE_HINTS = {
    "Google": "Google",
    "Amazon": "AWS",
    "Amazon Technologies": "AWS",
    "Amazon.com": "Amazon",
    "Microsoft": "Microsoft",
    "Azure": "Azure",
    "Cloudflare": "Cloudflare",
    "Cloudflare, Inc.": "Cloudflare",
    "Akamai": "Akamai",
    "Fastly": "Fastly",
    "Facebook": "Meta",
    "Meta": "Meta",
    "Twitter": "Twitter",
    "Telegram": "Telegram",
    "Discord": "Discord",
    "Netflix": "Netflix",
    "OVH": "OVH",
    "DigitalOcean": "DigitalOcean",
    "Linode": "Akamai",
    "Oracle": "Oracle",
    "Twitch": "Twitch",
}

SERVICE_IP_PREFIXES = {
    "2a00:1450:4017:": "YouTube",
    "2a00:1450:4013:": "YouTube",
    "2606:4700:": "Cloudflare",
    "2620:116:": "Cloudflare",
    "104.16.": "Cloudflare",
    "104.17.": "Cloudflare",
    "104.18.": "Cloudflare",
    "104.19.": "Cloudflare",
    "172.64.": "Cloudflare",
    "198.41.": "Cloudflare",
    "2001:4860:": "Google",
    "2a00:1450:": "Google",
    "2a01:831:": "Hetzner",
    "142.250.": "Google",
    "142.251.": "Google",
    "192.178.": "Google",
    "216.58.": "Google",
    "172.217.": "Google",
    "2600:9000:": "Amazon/AWS",
    "52.": "Amazon/AWS",
    "54.": "Amazon/AWS",
    "34.": "Google Cloud",
    "2a04:4e42:": "Fastly",
    "151.101.": "Fastly",
    "199.232.": "Fastly",
}

PROC_SERVICE_MAP = {
    "Discord": "Discord",
    "discord": "Discord",
    "Spotify": "Spotify",
    "spotify": "Spotify",
    "firefox": "Firefox",
    "thunderbird": "Thunderbird",
    "steam": "Steam",
    "Steam": "Steam",
    "signal-desktop": "Signal",
    "Element": "Element",
    "Skype": "Skype",
    "slack": "Slack",
    "WhatsApp": "WhatsApp",
    "teams": "Microsoft Teams",
    "Code": "VS Code",
    "code": "VS Code",
    "zoom": "Zoom",
    "Transmission": "BitTorrent",
    "qBittorrent": "BitTorrent",
    "deluge": "BitTorrent",
    "chromium-browser": "Chrome",
    "chrome": "Chrome",
    "Chromium": "Chrome",
    "opera": "Opera",
    "brave-browser": "Brave",
    "vivaldi": "Vivaldi",
    "telegram-desktop": "Telegram",
    "keepassxc": "KeePassXC",
    "syncthing": "Syncthing",
    "obs": "OBS Studio",
    "blender": "Blender",
    "docker": "Docker",
    "containerd": "Docker",
    "kubelet": "Kubernetes",
    "npm": "npm",
    "node": "Node.js",
    "python3": "Python",
    "python3.14": "Python",
    "curl": "curl",
    "wget": "wget",
    "git": "Git",
    "ssh": "SSH",
    "ncat": "Netcat",
    "rsync": "rsync",
}

KNOWN_APP_NAMES = set(PROC_SERVICE_MAP.keys()) | {
    "systemd", "dbus-daemon", "NetworkManager", "wpa_supplicant",
    "pulseaudio", "pipewire", "Xwayland", "kwin_wayland", "plasmashell",
    "kded6", "kaccess", " Discover", "PackageKit", "tracker-miner-fs-3",
    "baloo_file", "kscreen_backend", "powerdevil", "org_kde_powerdevil",
    "at-spi2-registryd", "gvfsd", "gvfs-goa-volume-monitor",
    "evolution-alarm-notify", "xfce4-notifyd",
}


def identify_service(hostname, ip, isp=""):
    if ip:
        for prefix, name in SERVICE_IP_PREFIXES.items():
            if ip.startswith(prefix):
                return name
    if hostname:
        hl = hostname.lower()
        for pattern, name in SERVICE_PATTERNS.items():
            if hl.endswith("." + pattern) or hl == pattern:
                return name
    if isp:
        for hint, name in ISP_SERVICE_HINTS.items():
            if hint.lower() in isp.lower():
                return name
    return None


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE) as f:
                s = json.load(f)
                for k, v in DEFAULT_SETTINGS.items():
                    s.setdefault(k, v)
                return s
        except Exception:
            pass
    return dict(DEFAULT_SETTINGS)


def save_settings_file(settings):
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
        log(f"Settings saved to {SETTINGS_FILE}")
    except Exception as e:
        log(f"Settings save error: {e}")


def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


# ----------------- SS PARSER -----------------
_RE = {k: re.compile(v) for k, v in {
    "sent": r"bytes_sent:(\d+)", "recv": r"bytes_received:(\d+)",
    "rtt": r"rtt:([\d.]+)/([\d.]+)", "cwnd": r"cwnd:(\d+)",
    "mss": r"mss:(\d+)", "retrans": r"retrans:(\d+)/(\d+)",
    "rto": r"rto:([\d.]+)", "swnd": r"snd_wnd:(\d+)",
    "rwnd": r"rcv_wnd:(\d+)", "drate": r"delivery_rate ([\d.]+)bps",
}.items()}


def _strip_brackets(addr):
    if addr.startswith("["):
        idx = addr.find("]:")
        if idx != -1:
            return addr[1:idx] + addr[idx+1:]
    return addr


def parse_ss():
    result = {}
    for proto_flag, proto_name in [("-tienp", "TCP"), ("-uienp", "UDP")]:
        try:
            out = subprocess.run(["ss", proto_flag], capture_output=True, text=True, timeout=3).stdout
            lines = out.strip().split("\n")
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if not line or line.startswith("State") or line.startswith("Recv"):
                    i += 1; continue
                parts = line.split()
                if len(parts) < 4:
                    i += 1; continue

                if proto_name == "TCP":
                    if len(parts) < 5:
                        i += 1; continue
                    state = parts[0]
                    local_addr_port = _strip_brackets(parts[3])
                    remote_addr_port = _strip_brackets(parts[4])
                else:
                    state = "UNCONN"
                    local_addr_port = _strip_brackets(parts[2])
                    remote_addr_port = _strip_brackets(parts[3])

                proc_name = "System"
                m = re.search(r'users:\(\("([^"]+)"', line)
                if m:
                    proc_name = m.group(1)

                key = (local_addr_port, remote_addr_port)
                stats = {"state": state, "proc": proc_name, "proto": proto_name,
                         "sent": 0, "recv": 0, "rtt": 0.0, "rtt_var": 0.0,
                         "cwnd": 0, "mss": 0, "retrans": 0, "rto": 0.0,
                         "swnd": 0, "rwnd": 0, "drate": 0.0}
                if proto_name == "TCP" and i + 1 < len(lines):
                    sl = lines[i + 1].strip()
                    if sl and not sl.startswith("State") and not sl.startswith("Recv"):
                        for rk, fn, t in [("sent", "sent", int), ("recv", "recv", int),
                                           ("cwnd", "cwnd", int), ("mss", "mss", int),
                                           ("swnd", "swnd", int), ("rwnd", "rwnd", int),
                                           ("retrans", "retrans", int), ("drate", "drate", float),
                                           ("rto", "rto", float)]:
                            m = _RE[rk].search(sl)
                            if m:
                                stats[fn] = t(m.group(1))
                        m = _RE["rtt"].search(sl)
                        if m:
                            stats["rtt"] = float(m.group(1))
                            stats["rtt_var"] = float(m.group(2))
                        i += 1
                result[key] = stats
                i += 1
        except Exception:
            pass
    return result


# ----------------- PROCESS CACHE -----------------
class ProcessCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
        self._cpu_interval = 0.1
        for p in psutil.process_iter(['pid']):
            try:
                p.cpu_percent(interval=0)
            except Exception:
                pass

    def get(self, pid):
        if not pid:
            return None
        with self.lock:
            if pid in self.cache:
                return self.cache[pid]
        try:
            p = psutil.Process(pid)
            info = {
                'name': p.name(),
                'exe': '',
                'cpu': 0.0,
                'memory': 0.0,
                'threads': 0,
            }
            try:
                info['exe'] = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info['exe'] = '?'
            try:
                info['cpu'] = p.cpu_percent(interval=0)
            except Exception:
                pass
            try:
                info['memory'] = p.memory_percent()
            except Exception:
                pass
            try:
                info['threads'] = p.num_threads()
            except Exception:
                pass
            with self.lock:
                self.cache[pid] = info
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def cleanup(self, active_pids):
        with self.lock:
            for pid in list(self.cache.keys()):
                if pid not in active_pids:
                    del self.cache[pid]


# ----------------- CONNECTION EVENT LOG -----------------
class ConnectionEventLog:
    def __init__(self, max_events=500):
        self.events = deque(maxlen=max_events)
        self.seen = set()
        self.lock = threading.Lock()

    def update(self, conns):
        current = set(conns.keys())
        with self.lock:
            for k in current - self.seen:
                c = conns[k]
                svc = c.get('service') or c.get('proc', '')
                log(f"CONNECTED: {c['ip']}:{c['port']} ({c['proto']}) via {svc}")
                self.events.appendleft({
                    'type': 'connect',
                    'time': time.time(),
                    'ip': c['ip'],
                    'port': c['port'],
                    'proc': c['proc'],
                    'service': c.get('service') or '',
                    'proto': c.get('proto', ''),
                })
            for k in self.seen - current:
                ip = k.split(':')[0] if ':' in k else k
                log(f"DISCONNECTED: {ip}")
                self.events.appendleft({
                    'type': 'disconnect',
                    'time': time.time(),
                    'key': k,
                    'proc': '',
                    'service': '',
                    'ip': ip,
                    'port': int(k.split(':')[1]) if ':' in k else 0,
                    'proto': '',
                })
            self.seen = current

    def get(self, limit=100):
        with self.lock:
            return list(self.events)[:limit]


# ----------------- SESSION RECORDER -----------------
class SessionRecorder:
    def __init__(self):
        self.recording = False
        self.session_file = None
        self.lock = threading.Lock()
        self.bytes_written = 0

    def start(self):
        with self.lock:
            if self.recording:
                return
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.session_file = os.path.join(RECORDINGS_DIR, f"session_{ts}.jsonl")
            self.recording = True
            self.bytes_written = 0

    def stop(self):
        with self.lock:
            self.recording = False
            f = self.session_file
            self.session_file = None
            return f

    def is_recording(self):
        return self.recording

    def record(self, conns, speed, io):
        if not self.recording:
            return
        with self.lock:
            if not self.session_file:
                return
            try:
                entry = {
                    't': round(time.time(), 2),
                    'dl': round(speed['dl'], 2),
                    'ul': round(speed['ul'], 2),
                    'tot': io.bytes_sent + io.bytes_recv,
                    'n': len(conns),
                }
                with open(self.session_file, 'a') as f:
                    f.write(json.dumps(entry) + '\n')
                    self.bytes_written += len(json.dumps(entry)) + 1
            except Exception:
                pass

    def get_status(self):
        return {
            'recording': self.recording,
            'file': os.path.basename(self.session_file) if self.session_file else None,
            'bytes': self.bytes_written,
        }


# ----------------- BANDWIDTH ALERT MONITOR -----------------
class BandwidthAlertMonitor:
    def __init__(self):
        self.dl_threshold = 0
        self.ul_threshold = 0
        self.cooldown = 30
        self.last_alert_dl = 0
        self.last_alert_ul = 0
        self.alerts = deque(maxlen=100)
        self.window = None
        self.lock = threading.Lock()

    def configure(self, dl_kb, ul_kb, cooldown=30):
        with self.lock:
            self.dl_threshold = dl_kb
            self.ul_threshold = ul_kb
            self.cooldown = cooldown

    def check(self, dl_kbs, ul_kbs):
        now = time.time()
        triggered = []
        with self.lock:
            if self.dl_threshold > 0 and dl_kbs > self.dl_threshold and now - self.last_alert_dl > self.cooldown:
                self.last_alert_dl = now
                alert = {'time': now, 'direction': 'Download', 'speed': round(dl_kbs, 1),
                         'threshold': self.dl_threshold}
                self.alerts.appendleft(alert)
                triggered.append(alert)
            if self.ul_threshold > 0 and ul_kbs > self.ul_threshold and now - self.last_alert_ul > self.cooldown:
                self.last_alert_ul = now
                alert = {'time': now, 'direction': 'Upload', 'speed': round(ul_kbs, 1),
                         'threshold': self.ul_threshold}
                self.alerts.appendleft(alert)
                triggered.append(alert)
        for alert in triggered:
            if self.window:
                try:
                    self.window.evaluate_js(f"window.showAlert({json.dumps(alert)})")
                except Exception:
                    pass

    def get_alerts(self, limit=50):
        with self.lock:
            return list(self.alerts)[:limit]


# ----------------- SPEED TEST -----------------
class SpeedTestRunner:
    def __init__(self):
        self.last_result = None
        self.running = False
        self.lock = threading.Lock()

    def run_async(self):
        with self.lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def _run(self):
        try:
            result = subprocess.run(
                ['speedtest-cli', '--json'],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                with self.lock:
                    self.last_result = {
                        'download': round(data.get('download', 0) / 1_000_000, 2),
                        'upload': round(data.get('upload', 0) / 1_000_000, 2),
                        'ping': round(data.get('ping', 0), 1),
                        'server': data.get('server', {}).get('name', '?'),
                        'client': data.get('client', {}).get('isp', '?'),
                        'time': time.time(),
                    }
        except Exception:
            pass
        with self.lock:
            self.running = False

    def get_result(self):
        with self.lock:
            return {'running': self.running, 'result': self.last_result}


# ----------------- SUMMARY TRACKER -----------------
class SummaryTracker:
    def __init__(self):
        self.path = os.path.join(DATA_DIR, "summaries.json")
        self.hourly = {}
        self.app_usage = {}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                    self.hourly = data.get('hourly', {})
                    self.app_usage = data.get('app_usage', {})
            except Exception:
                pass

    def save(self):
        try:
            with open(self.path, 'w') as f:
                json.dump({'hourly': self.hourly, 'app_usage': self.app_usage}, f, indent=2)
        except Exception:
            pass

    def update(self, io, dl_kbs, ul_kbs, conns):
        hour_key = datetime.now().strftime('%Y-%m-%d_%H')
        if hour_key not in self.hourly:
            self.hourly[hour_key] = {
                'ts': io.bytes_sent + io.bytes_recv,
                'bs': io.bytes_sent,
                'br': io.bytes_recv,
                'pdl': dl_kbs, 'pul': ul_kbs,
                'n': 0,
            }
        h = self.hourly[hour_key]
        h['bs'] = io.bytes_sent
        h['br'] = io.bytes_recv
        h['pdl'] = max(h['pdl'], dl_kbs)
        h['pul'] = max(h['pul'], ul_kbs)
        h['n'] = len(conns)

        for c in conns:
            name = c.get('service') or c.get('proc') or 'Unknown'
            if name not in self.app_usage:
                self.app_usage[name] = {'sent': 0, 'recv': 0, 'last': 0}
            au = self.app_usage[name]
            delta_sent = max(0, c.get('sent', 0) - au.get('last_sent', 0))
            delta_recv = max(0, c.get('recv', 0) - au.get('last_recv', 0))
            if c.get('sent', 0) >= au.get('last_sent', 0):
                au['sent'] += delta_sent
            if c.get('recv', 0) >= au.get('last_recv', 0):
                au['recv'] += delta_recv
            au['last_sent'] = c.get('sent', 0)
            au['last_recv'] = c.get('recv', 0)
            au['last'] = time.time()

    def get_period_summary(self, period='day'):
        now = datetime.now()
        if period == 'day':
            cutoff = now - timedelta(days=1)
        elif period == 'week':
            cutoff = now - timedelta(weeks=1)
        elif period == 'month':
            cutoff = now - timedelta(days=30)
        else:
            cutoff = now - timedelta(days=365)

        total_dl = 0
        total_ul = 0
        peak_dl = 0
        peak_ul = 0
        hours = []
        for hk, hv in sorted(self.hourly.items()):
            try:
                dt = datetime.strptime(hk, '%Y-%m-%d_%H')
                if dt >= cutoff:
                    peak_dl = max(peak_dl, hv.get('pdl', 0))
                    peak_ul = max(peak_ul, hv.get('pul', 0))
                    hours.append({'hour': hk, 'dl': hv.get('pdl', 0), 'ul': hv.get('pul', 0),
                                  'conn': hv.get('n', 0)})
            except Exception:
                pass
        return {
            'period': period,
            'total_hours': len(hours),
            'peak_dl': round(peak_dl, 2),
            'peak_ul': round(peak_ul, 2),
            'hours': hours,
        }

    def get_app_usage(self, limit=20):
        sorted_apps = sorted(self.app_usage.items(),
                             key=lambda x: x[1].get('sent', 0) + x[1].get('recv', 0),
                             reverse=True)[:limit]
        return [{'name': n, 'sent': v.get('sent', 0), 'recv': v.get('recv', 0)} for n, v in sorted_apps]

    def cleanup_old(self, days=90):
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d_%H')
        self.hourly = {k: v for k, v in self.hourly.items() if k >= cutoff}


# ----------------- GEO IP RESOLVER -----------------
class IPResolver:
    def __init__(self, geo_cache, callback):
        self.geo_cache = geo_cache
        self.callback = callback
        self.queue = deque()
        self.lock = threading.Lock()
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def queue_ip(self, ip):
        if not ip:
            return
        low = ip.lower()
        if low in ("127.0.0.1", "::1", "fe80::1", "0.0.0.0"):
            return
        if low.startswith("192.168.") or low.startswith("10.") or low.startswith("169.254."):
            return
        if low.startswith("172."):
            try:
                if 16 <= int(low.split(".")[1]) <= 31:
                    return
            except (IndexError, ValueError):
                pass
        if low.startswith("fe80:") or low.startswith("ff00:") or low.startswith("fc00:") or low.startswith("fd00:"):
            return
        with self.lock:
            if ip not in self.geo_cache and ip not in self.queue:
                self.queue.append(ip)

    def _run(self):
        while self.running:
            batch = []
            with self.lock:
                while self.queue and len(batch) < 10:
                    batch.append(self.queue.popleft())
            if batch:
                try:
                    payload = [{"query": ip, "fields": "status,country,city,lat,lon,isp,org"} for ip in batch]
                    r = requests.post("http://ip-api.com/batch", json=payload, timeout=5)
                    if r.status_code == 200:
                        results = r.json()
                        for ip, res in zip(batch, results):
                            if res.get("status") == "success":
                                self.callback(ip, {"lat": res["lat"], "lon": res["lon"],
                                                    "country": res.get("country", "?"), "city": res.get("city", "?"),
                                                    "isp": res.get("isp") or res.get("org") or "?"})
                            else:
                                self.callback(ip, None)
                    else:
                        for ip in batch:
                            self.callback(ip, None)
                except Exception:
                    with self.lock:
                        for ip in batch:
                            if ip not in self.queue:
                                self.queue.append(ip)
                time.sleep(1.5)
            else:
                time.sleep(0.2)

    def stop(self):
        self.running = False


# ----------------- DOMAIN RESOLVER -----------------
SERVICE_DOMAINS = {
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com"],
    "Instagram": ["instagram.com", "cdninstagram.com"],
    "Discord": ["discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net"],
    "Spotify": ["open.spotify.com", "api.spotify.com", "spotify.com"],
    "Twitch": ["twitch.tv", "jtvnw.net", "ttvnw.net"],
    "Reddit": ["reddit.com", "redditstatic.com", "redditmedia.com"],
    "Twitter/X": ["twitter.com", "x.com", "api.x.com", "twimg.com"],
    "Facebook": ["facebook.com", "fbcdn.net"],
    "Telegram": ["telegram.org", "t.me"],
    "GitHub": ["github.com", "api.github.com", "github.io"],
    "Microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "windows.com"],
    "Amazon": ["amazon.com", "amazonaws.com"],
    "Apple": ["apple.com", "icloud.com"],
    "Steam": ["steampowered.com", "steamcontent.com", "steamstatic.com", "valve.net"],
    "Cloudflare": ["cloudflare.com", "cloudflareinsights.com"],
    "Wikipedia": ["wikipedia.org", "wikimedia.org"],
    "Zoom": ["zoom.us"],
    "Slack": ["slack.com", "slack-edge.com"],
    "WhatsApp": ["whatsapp.com"],
    "PayPal": ["paypal.com"],
    "eBay": ["ebay.com"],
    "Mozilla": ["mozilla.org", "firefox.com"],
    "Temu": ["temu.com"],
}


class DomainResolver:
    def __init__(self, cache):
        self.cache = cache
        self._queue = deque()
        self.lock = threading.Lock()
        self.running = True
        self._dns_map = {}
        self._forward_map = {}
        self._service_prefixes = {}
        threading.Thread(target=self._build_forward_map, daemon=True).start()
        threading.Thread(target=self._run, daemon=True).start()

    def queue(self, ip):
        if not ip:
            return
        low = ip.lower()
        if low in ("127.0.0.1", "::1", "fe80::1", "0.0.0.0"):
            return
        if low.startswith("192.168.") or low.startswith("10.") or low.startswith("169.254."):
            return
        if low.startswith("172."):
            try:
                if 16 <= int(low.split(".")[1]) <= 31:
                    return
            except (IndexError, ValueError):
                pass
        if low.startswith("fe80:") or low.startswith("ff00:") or low.startswith("fc00:") or low.startswith("fd00:"):
            return
        key = f"_domain_{ip}"
        with self.lock:
            if key not in self.cache and ip not in self._queue:
                self._queue.append(ip)

    def get(self, ip):
        if not ip:
            return None
        key = f"_domain_{ip}"
        val = self.cache.get(key)
        if isinstance(val, dict):
            return val
        return None

    def get_service_by_prefix(self, ip):
        if not ip:
            return None
        with self.lock:
            if ip in self._service_prefixes:
                return self._service_prefixes[ip]
        return None

    def _build_forward_map(self):
        fwd = {}
        prefixes = {}
        socket.setdefaulttimeout(3)
        for service, domains in SERVICE_DOMAINS.items():
            for d in domains:
                try:
                    addrs = socket.getaddrinfo(d, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    for family, _, _, _, sockaddr in addrs:
                        addr = sockaddr[0]
                        fwd[addr] = d
                        if ":" in addr:
                            prefix = ":".join(addr.split(":")[:3])
                        else:
                            prefix = ".".join(addr.split(".")[:3]) + "."
                        prefixes[addr] = (prefix, service)
                except Exception:
                    pass
        with self.lock:
            self._forward_map = fwd
            self._service_prefixes = prefixes

    def _resolve(self, ip):
        with self.lock:
            if ip in self._forward_map:
                return self._forward_map[ip]
            if ip in self._dns_map:
                return self._dns_map[ip]
        try:
            r = subprocess.run(["getent", "hosts", ip],
                               capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and r.stdout.strip():
                parts = r.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1]
                    if hostname.endswith(".in-addr.arpa") or hostname.endswith(".ip6.arpa"):
                        return None
                    return hostname
        except Exception:
            pass
        return None

    def _run(self):
        while self.running:
            ip = None
            with self.lock:
                if self._queue:
                    ip = self._queue.popleft()
            if ip:
                hostname = self._resolve(ip)
                geo = self.cache.get(ip, {})
                isp = geo.get("isp", "") if isinstance(geo, dict) else ""
                service = identify_service(hostname, ip, isp)
                if not service:
                    prefix_info = self.get_service_by_prefix(ip)
                    if prefix_info:
                        service = prefix_info[1]
                entry = {"hostname": hostname, "service": service}
                self.cache[f"_domain_{ip}"] = entry
                time.sleep(0.1)
            else:
                time.sleep(0.5)

    def stop(self):
        self.running = False


# ----------------- CONNECTION TRACKER -----------------
class ConnectionTracker:
    def __init__(self, resolver, domain_resolver, process_cache, event_log):
        self.resolver = resolver
        self.domain_resolver = domain_resolver
        self.process_cache = process_cache
        self.event_log = event_log
        self.conns = {}
        self.meta = {}
        self.lock = threading.Lock()
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while self.running:
            now = time.time()
            new = {}
            try:
                ss = parse_ss()
                active_pids = set()
                for c in psutil.net_connections(kind='inet'):
                    if not c.raddr: continue
                    rip, rport = c.raddr.ip, c.raddr.port
                    lip, lport = c.laddr.ip, c.laddr.port
                    rlow = rip.lower()
                    if rlow in ("127.0.0.1", "::1", "0.0.0.0") or rlow.startswith("192.168.") or rlow.startswith("10.") or rlow.startswith("169.254."):
                        continue
                    if rlow.startswith("172."):
                        try:
                            if 16 <= int(rlow.split(".")[1]) <= 31:
                                continue
                        except (IndexError, ValueError):
                            pass
                    if rlow.startswith("fe80:") or rlow.startswith("ff00:") or rlow.startswith("fc00:") or rlow.startswith("fd00:"):
                        continue
                    pid = c.pid
                    pname = "System"
                    if pid:
                        try: pname = psutil.Process(pid).name()
                        except: pname = "Unknown"
                        active_pids.add(pid)

                    ck = f"{rip}:{rport}"
                    lk = f"{lip}:{lport}"
                    entry = {"ip": rip, "port": rport, "lip": lip, "lport": lport,
                             "pid": pid, "proc": pname, "state": c.status,
                             "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                             "sent": 0, "recv": 0, "spd_up": 0.0, "spd_dn": 0.0,
                             "rtt": 0.0, "rtt_var": 0.0, "cwnd": 0, "mss": 0,
                             "retrans": 0, "rto": 0.0, "swnd": 0, "rwnd": 0, "drate": 0.0,
                             "first_seen": now, "port_service": PORT_SERVICE_MAP.get(rport, '')}

                    for sk in [(lk, f"{rip}:{rport}"), (f"{rip}:{rport}", lk)]:
                        if sk in ss:
                            s = ss[sk]
                            for f in ["sent", "recv", "rtt", "rtt_var", "cwnd", "mss",
                                      "retrans", "rto", "swnd", "rwnd", "drate"]:
                                entry[f] = s[f]
                            break

                    with self.lock:
                        m = self.meta.get(ck)
                        if not m:
                            m = {"first": now, "ps": entry["sent"], "pr": entry["recv"], "pt": now}
                            self.meta[ck] = m
                        entry["first_seen"] = m["first"]
                        dt = now - m["pt"]
                        if dt > 0.3:
                            entry["spd_up"] = max(0, entry["sent"] - m["ps"]) / dt
                            entry["spd_dn"] = max(0, entry["recv"] - m["pr"]) / dt
                            m["ps"] = entry["sent"]
                            m["pr"] = entry["recv"]
                            m["pt"] = now

                    domain_info = self.domain_resolver.get(rip)
                    if domain_info and isinstance(domain_info, dict):
                        entry["hostname"] = domain_info.get("hostname")
                        entry["service"] = domain_info.get("service")
                    else:
                        entry["hostname"] = None
                        entry["service"] = None
                    if not entry["service"] and pname in PROC_SERVICE_MAP:
                        entry["service"] = PROC_SERVICE_MAP[pname]
                    self.domain_resolver.queue(rip)
                    new[ck] = entry
                    self.resolver.queue_ip(rip)

                with self.lock:
                    for k in [k for k in self.meta if k not in new]:
                        del self.meta[k]
                self.process_cache.cleanup(active_pids)
                self.event_log.update(new)
            except Exception as e:
                log(f"ConnectionTracker error: {e}")
            with self.lock:
                self.conns = new
            time.sleep(0.5)

    def get(self):
        with self.lock:
            return dict(self.conns)

    def stop(self):
        self.running = False


# ----------------- NEW MONITORS -----------------

class ProcessBandwidthTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.prev_time = time.time()
        self.data = {}

    def update(self, conns_list):
        now = time.time()
        dt = now - self.prev_time
        if dt <= 0:
            return
        proc_bytes = {}
        for c in conns_list:
            p = c.get("proc", "?")
            if p not in proc_bytes:
                proc_bytes[p] = {"sent": 0, "recv": 0}
            proc_bytes[p]["sent"] += c.get("spd_up", 0) * dt
            proc_bytes[p]["recv"] += c.get("spd_dn", 0) * dt
        with self.lock:
            for p, b in proc_bytes.items():
                if p not in self.data:
                    self.data[p] = {"sent": 0, "recv": 0, "dl": 0, "ul": 0}
                self.data[p]["dl"] = b["recv"] / dt / 1024
                self.data[p]["ul"] = b["sent"] / dt / 1024
                self.data[p]["sent"] += int(b["sent"])
                self.data[p]["recv"] += int(b["recv"])
            gone = set(self.data) - set(proc_bytes)
            for p in gone:
                self.data[p]["dl"] = 0
                self.data[p]["ul"] = 0
        self.prev_time = now

    def get(self):
        with self.lock:
            return dict(self.data)


class SystemMonitor:
    def __init__(self):
        psutil.cpu_percent(interval=0)
        self.disk_io_prev = psutil.disk_io_counters() if hasattr(psutil, 'disk_io_counters') else None
        self.disk_prev_time = time.time()
        self.cpu_temp = 0
        self.gpu_temp = 0

    def _read_temps(self):
        try:
            temps = psutil.sensors_temperatures()
            for name in ("coretemp", "k10temp", "cpu_thermal", "acpitz"):
                if name in temps and temps[name]:
                    vals = [t.current for t in temps[name] if t.current > 0]
                    if vals:
                        self.cpu_temp = round(max(vals), 1)
                        break
            for name in ("amdgpu", "nvidia", "nouveau", "radeon", "nvidia_gpu", "gpu_thermal"):
                if name in temps and temps[name]:
                    vals = [t.current for t in temps[name] if t.current > 0]
                    if vals:
                        self.gpu_temp = round(max(vals), 1)
                        break
            if self.gpu_temp == 0:
                try:
                    out = subprocess.check_output(
                        ["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"],
                        stderr=subprocess.DEVNULL, timeout=3
                    ).decode().strip()
                    if out:
                        self.gpu_temp = float(out.splitlines()[0])
                except Exception:
                    pass
        except Exception:
            pass

    def get(self):
        self._read_temps()
        cpu = psutil.cpu_percent(interval=0)
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk_read = disk_write = 0.0
        if self.disk_io_prev and hasattr(psutil, 'disk_io_counters'):
            try:
                dio = psutil.disk_io_counters()
                dt = time.time() - self.disk_prev_time
                if dt > 0:
                    disk_read = (dio.read_bytes - self.disk_io_prev.read_bytes) / dt / 1024 / 1024
                    disk_write = (dio.write_bytes - self.disk_io_prev.write_bytes) / dt / 1024 / 1024
                self.disk_io_prev = dio
                self.disk_prev_time = time.time()
            except Exception:
                pass
        return {
            "cpu": round(cpu, 1),
            "ram_used": vm.used,
            "ram_total": vm.total,
            "ram_pct": round(vm.percent, 1),
            "swap_used": swap.used,
            "swap_total": swap.total,
            "swap_pct": round(swap.percent, 1),
            "disk_read": round(disk_read, 1),
            "disk_write": round(disk_write, 1),
            "cpu_temp": self.cpu_temp,
            "gpu_temp": self.gpu_temp,
        }


class WiFiMonitor:
    def __init__(self):
        self.signal = 0
        self.ssid = ""
        self.freq = ""
        self.speed = ""

    def update(self):
        try:
            out = subprocess.check_output(
                ["iwconfig"], stderr=subprocess.DEVNULL, timeout=2
            ).decode("utf-8", errors="ignore")
            sig = re.search(r"Signal level=(-?\d+)", out)
            if sig:
                self.signal = int(sig.group(1))
            essid = re.search(r'ESSID:"(.+?)"', out)
            if essid:
                self.ssid = essid.group(1)
            freq = re.search(r"Frequency:(\S+)", out)
            if freq:
                self.freq = freq.group(1)
            bitrate = re.search(r"Bit Rate=(\S+)", out)
            if bitrate:
                self.speed = bitrate.group(1)
        except Exception:
            try:
                wpath = "/proc/net/wireless"
                if os.path.exists(wpath):
                    with open(wpath) as f:
                        lines = f.readlines()
                    if len(lines) > 1:
                        parts = lines[1].split()
                        if len(parts) >= 4:
                            self.signal = int(parts[2])
            except Exception:
                pass

    def get(self):
        self.update()
        return {"signal": self.signal, "ssid": self.ssid, "freq": self.freq, "speed": self.speed}


class PingMonitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.targets = {}
        self.history = {}

    def ping(self, host, count=3):
        try:
            out = subprocess.check_output(
                ["ping", "-c", str(count), "-W", "2", host],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode("utf-8", errors="ignore")
            avg = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out)
            loss = re.search(r"(\d+)% packet loss", out)
            jitter = re.search(r"mdev = ([\d.]+) ms", out)
            rtt = float(avg.group(1)) if avg else 0
            pkt_loss = float(loss.group(1)) if loss else 100
            jitt = float(jitter.group(1)) if jitter else 0
            return {"rtt": rtt, "loss": pkt_loss, "jitter": jitt}
        except Exception:
            return {"rtt": 0, "loss": 100, "jitter": 0}

    def track(self, host):
        threading.Thread(target=self._track_host, args=(host,), daemon=True).start()

    def _track_host(self, host):
        result = self.ping(host)
        with self.lock:
            if host not in self.history:
                self.history[host] = deque(maxlen=30)
            self.history[host].append({"time": time.time(), **result})
            self.targets[host] = result

    def get(self):
        with self.lock:
            return {
                "targets": dict(self.targets),
                "history": {k: list(v) for k, v in self.history.items()},
            }


class VPNDetector:
    VPN_PATTERNS = {"tun", "wg", "ppp", "tap", "vpn", "wireguard", "tailscale", "zerotier"}

    def detect(self):
        interfaces = psutil.net_if_stats()
        vpn_names = []
        for name in interfaces:
            if any(p in name.lower() for p in self.VPN_PATTERNS):
                vpn_names.append(name)
        if not vpn_names:
            try:
                out = subprocess.check_output(
                    ["ip", "link", "show"], stderr=subprocess.DEVNULL, timeout=2
                ).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    m = re.search(r"\d+:\s+(\S+?):", line)
                    if m:
                        iname = m.group(1)
                        if any(p in iname.lower() for p in self.VPN_PATTERNS):
                            if iname not in vpn_names:
                                vpn_names.append(iname)
            except Exception:
                pass
        active = False
        for n in vpn_names:
            st = interfaces.get(n)
            if st and st.isup:
                active = True
                break
        return {"active": active, "interfaces": vpn_names}


class PortScanDetector:
    def __init__(self, threshold=15):
        self.lock = threading.Lock()
        self.connections = {}
        self.alerts = deque(maxlen=100)
        self.threshold = threshold

    def update(self, conns_list):
        now = time.time()
        ip_conns = {}
        for c in conns_list:
            ip = c.get("ip", "")
            port = c.get("port", 0)
            if ip and port:
                if ip not in ip_conns:
                    ip_conns[ip] = set()
                ip_conns[ip].add(port)
        with self.lock:
            self.connections = {}
            for ip, ports in ip_conns.items():
                self.connections[ip] = {"ports": len(ports), "list": sorted(ports)[:20]}
                if len(ports) >= self.threshold:
                    exists = any(a["ip"] == ip and now - a["time"] < 60 for a in self.alerts)
                    if not exists:
                        log(f"PORT SCAN ALERT: {ip} hitting {len(ports)} ports")
                        self.alerts.append({
                            "ip": ip, "ports": len(ports),
                            "time": now, "sample": sorted(ports)[:10],
                        })

    def get(self):
        with self.lock:
            return {
                "scans": [a for a in self.alerts if time.time() - a["time"] < 300],
                "top_targets": sorted(self.connections.items(),
                                       key=lambda x: x[1]["ports"], reverse=True)[:10],
            }


class DNSQueryLogger:
    def __init__(self):
        self.lock = threading.Lock()
        self.queries = deque(maxlen=200)
        self.ip_to_domain = {}
        self.proc = None
        self._start_capture()

    def _start_capture(self):
        def _run():
            try:
                self.proc = subprocess.Popen(
                    ["tshark", "-i", "any", "-f", "port 53", "-T", "fields",
                     "-e", "frame.time", "-e", "dns.qry.name", "-e", "dns.flags.response",
                     "-e", "dns.a", "-e", "dns.aaaa", "-l"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
                )
                for line in self.proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) < 3:
                        continue
                    is_response = parts[2] == "1" if len(parts) > 2 else False
                    domain = parts[1] if len(parts) > 1 else ""
                    if not domain:
                        continue
                    with self.lock:
                        if is_response:
                            resolved_ips = []
                            if len(parts) > 3 and parts[3]:
                                resolved_ips.extend(parts[3].split(","))
                            if len(parts) > 4 and parts[4]:
                                resolved_ips.extend(parts[4].split(","))
                            for rip in resolved_ips:
                                rip = rip.strip()
                                if rip:
                                    self.ip_to_domain[rip] = domain
                                    if len(self.ip_to_domain) > 5000:
                                        oldest = list(self.ip_to_domain.keys())[:1000]
                                        for k in oldest:
                                            self.ip_to_domain.pop(k, None)
                        else:
                            self.queries.append({
                                "time": time.time(),
                                "domain": domain,
                                "type": "query",
                            })
            except FileNotFoundError:
                log("tshark not found - DNS capture disabled")
            except Exception as e:
                log(f"DNS capture error: {e}")
        threading.Thread(target=_run, daemon=True).start()

    def get(self):
        with self.lock:
            return list(self.queries)[-50:]

    def resolve_service_from_dns(self, ip):
        with self.lock:
            domain = self.ip_to_domain.get(ip, "")
        if not domain:
            return None
        dl = domain.lower()
        youtube_patterns = ("youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
                            "youtu.be", "youtube-nocookie.com")
        for pat in youtube_patterns:
            if pat in dl:
                return "YouTube"
        return None


class LANDiscovery:
    def __init__(self):
        self.lock = threading.Lock()
        self.devices = []
        self.scanning = False

    def scan(self):
        if self.scanning:
            return
        self.scanning = True
        threading.Thread(target=self._scan, daemon=True).start()

    def _scan(self):
        devices = []
        try:
            out = subprocess.check_output(
                ["arp-scan", "--localnet", "--retry=1", "--timeout=500"],
                stderr=subprocess.DEVNULL, timeout=15
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                m = re.match(r"([\d.]+)\s+([\da-fA-F:]{17})", line)
                if m:
                    ip, mac = m.group(1), m.group(2)
                    try:
                        h = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        h = ""
                    devices.append({"ip": ip, "mac": mac, "hostname": h})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                out = subprocess.check_output(
                    ["ip", "neigh", "show"], stderr=subprocess.DEVNULL, timeout=5
                ).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[3] == "REACHABLE":
                        devices.append({"ip": parts[0], "mac": parts[4] if len(parts) > 4 else "", "hostname": ""})
            except Exception:
                pass
        except Exception:
            pass
        with self.lock:
            self.devices = devices
        self.scanning = False

    def get(self):
        with self.lock:
            return self.devices


# ----------------- API BRIDGE -----------------
class Api:
    def __init__(self):
        self.geo = load_cache()
        self.settings = load_settings()
        self.home = {"lat": 30.0, "lon": 0.0, "ip": "?", "city": "?", "country": "?", "isp": "?"}
        self.home_ready = threading.Event()
        self.window = None
        self.session_start = time.time()
        self.session_sent = 0
        self.session_recv = 0

        self.process_cache = ProcessCache()
        self.event_log = ConnectionEventLog()
        self.session_recorder = SessionRecorder()
        self.alert_monitor = BandwidthAlertMonitor()
        self.speed_tester = SpeedTestRunner()
        self.summary_tracker = SummaryTracker()
        self.unknown_apps = set()
        self.trace_results = {}
        self.trace_cache_time = {}
        self._trace_running = False
        self._trace_all_progress = None
        self._log_buffer = []
        self._log_lock = threading.Lock()

        self.alert_monitor.configure(
            self.settings.get('alert_dl_threshold', 0),
            self.settings.get('alert_ul_threshold', 0),
            self.settings.get('alert_cooldown', 30),
        )

        self.resolver = IPResolver(self.geo, self._on_resolved)
        self.domain_resolver = DomainResolver(self.geo)
        self.tracker = ConnectionTracker(self.resolver, self.domain_resolver, self.process_cache, self.event_log)

        self.proc_bw = ProcessBandwidthTracker()
        self.sys_monitor = SystemMonitor()
        self.wifi_monitor = WiFiMonitor()
        self.ping_monitor = PingMonitor()
        self.vpn_detector = VPNDetector()
        self.port_scanner = PortScanDetector()
        self.dns_logger = DNSQueryLogger()
        self.lan_discovery = LANDiscovery()

        threading.Thread(target=self._resolve_home, daemon=True).start()
        threading.Thread(target=self._monitor, daemon=True).start()

    def set_window(self, w):
        self.window = w
        self.alert_monitor.window = w

    def _on_resolved(self, ip, data):
        if data:
            self.geo[ip] = data
        else:
            self.geo[ip] = {"lat": None, "lon": None, "country": "?", "city": "?", "isp": "?"}
        save_cache(self.geo)

    def _resolve_home(self):
        try:
            r = requests.get("http://ip-api.com/json/?fields=status,country,city,lat,lon,query,isp", timeout=4)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    self.home = {"lat": d["lat"], "lon": d["lon"], "ip": d.get("query", "?"),
                                 "city": d.get("city", "?"), "country": d.get("country", "?"),
                                 "isp": d.get("isp", "?")}
                    self.home_ready.set()
                    self._push_home()
                    return
        except Exception:
            pass
        self.home = {"lat": 38.8951, "lon": -77.0364, "ip": "Offline", "city": "Local", "country": "Network", "isp": "Gateway"}
        self.home_ready.set()
        self._push_home()

    def _push_home(self):
        if self.window:
            try:
                self.window.evaluate_js(f"window.pushHomeUpdate({json.dumps(self.home)})")
            except Exception:
                pass

    def _monitor(self):
        prev_io = psutil.net_io_counters()
        prev_t = time.time()
        dl_hist = deque([0.0] * 120, maxlen=120)
        ul_hist = deque([0.0] * 120, maxlen=120)
        tick = 0

        while True:
            time.sleep(0.25)
            now = time.time()
            io = psutil.net_io_counters()
            dt = now - prev_t
            if dt > 0:
                dl = ((io.bytes_recv - prev_io.bytes_recv) / dt) / 1024.0
                ul = ((io.bytes_sent - prev_io.bytes_sent) / dt) / 1024.0
                dl_hist.append(dl)
                ul_hist.append(ul)
            else:
                dl = dl_hist[-1] if dl_hist else 0
                ul = ul_hist[-1] if ul_hist else 0
            prev_io = io
            prev_t = now

            conns = self.tracker.get()
            conns_list = list(conns.values())

            for c in conns_list:
                if not c.get("service") or c.get("service") == "Google":
                    dns_svc = self.dns_logger.resolve_service_from_dns(c["ip"])
                    if dns_svc:
                        c["service"] = dns_svc

            proto_cnt = Counter(c["proto"] for c in conns_list)
            state_cnt = Counter(c["state"] for c in conns_list)
            proc_cnt = Counter(c["proc"] for c in conns_list)
            top_procs = [{"name": n, "count": c} for n, c in proc_cnt.most_common(8)]

            rtts = [c["rtt"] for c in conns_list if c["rtt"] > 0]
            avg_rtt = sum(rtts) / len(rtts) if rtts else 0

            mapped = sum(1 for c in conns_list
                         if c["ip"] in self.geo and self.geo[c["ip"]].get("lat") is not None)

            self.session_sent = io.bytes_sent
            self.session_recv = io.bytes_recv
            session_dur = time.time() - self.session_start

            country_cnt = Counter()
            for c in conns_list:
                g = self.geo.get(c["ip"], {})
                country = g.get("country", "?") if isinstance(g, dict) else "?"
                country_cnt[country] += 1

            self.alert_monitor.check(dl, ul)

            tick += 1
            if tick % 10 == 0:
                self.summary_tracker.update(io, dl, ul, conns_list)
                self.proc_bw.update(conns_list)
                self.port_scanner.update(conns_list)
                if tick % 60 == 0:
                    self.summary_tracker.save()
                if tick % 40 == 0:
                    self.wifi_monitor.update()

            if self.session_recorder.is_recording():
                self.session_recorder.record(conns_list, {"dl": dl, "ul": ul}, io)

            for c in conns_list:
                pname = c.get('proc', '')
                if pname and pname not in KNOWN_APP_NAMES and pname != 'System' and pname != 'Unknown':
                    self.unknown_apps.add(pname)

            payload = {
                "speed": {"dl": round(dl_hist[-1], 2), "ul": round(ul_hist[-1], 2)},
                "totals": {"sent": io.bytes_sent, "recv": io.bytes_recv},
                "dl_hist": list(dl_hist), "ul_hist": list(ul_hist),
                "conns": conns_list,
                "geo": {k: v for k, v in self.geo.items() if isinstance(v, dict) and v.get("lat") is not None},
                "home": self.home,
                "stats": {
                    "total": len(conns_list), "mapped": mapped,
                    "tcp": proto_cnt.get("TCP", 0), "udp": proto_cnt.get("UDP", 0),
                    "states": dict(state_cnt),
                    "avg_rtt": round(avg_rtt, 1),
                    "top_procs": top_procs,
                    "countries": dict(country_cnt.most_common(10)),
                },
                "session": {
                    "start": self.session_start,
                    "duration": round(session_dur),
                    "sent": self.session_sent,
                    "recv": self.session_recv,
                },
                "process_details": self._get_process_details_batch(conns_list),
                "recording": self.session_recorder.get_status(),
                "proc_bw": self.proc_bw.get(),
                "system": self.sys_monitor.get(),
                "wifi": self.wifi_monitor.get(),
                "vpn": self.vpn_detector.detect(),
                "port_scans": self.port_scanner.get(),
                "dns": self.dns_logger.get(),
            }

            if self.window:
                try:
                    self.window.evaluate_js(f"window.pushUpdate({json.dumps(payload)})")
                except Exception as e:
                    log(f"JS push error: {e}")

    def _get_process_details_batch(self, conns_list):
        pids = set(c.get('pid') for c in conns_list if c.get('pid'))
        result = {}
        for pid in pids:
            info = self.process_cache.get(pid)
            if info:
                result[pid] = info
        return result

    # JS-callable methods
    def get_initial(self):
        return json.dumps({"settings": self.settings, "home": self.home})

    def get_connections(self):
        conns = self.tracker.get()
        conns_list = list(conns.values())
        for c in conns_list:
            if not c.get("service") or c.get("service") == "Google":
                dns_svc = self.dns_logger.resolve_service_from_dns(c["ip"])
                if dns_svc:
                    c["service"] = dns_svc
        io = psutil.net_io_counters()
        return json.dumps({
            "conns": conns_list,
            "geo": {k: v for k, v in self.geo.items() if isinstance(v, dict) and v.get("lat") is not None},
            "home": self.home,
        })

    def lookup_ip(self, query):
        try:
            ip = socket.gethostbyname(query)
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org", timeout=3)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    data = {"lat": d["lat"], "lon": d["lon"], "country": d.get("country", "?"),
                            "city": d.get("city", "?"), "isp": d.get("isp") or d.get("org") or "?"}
                    self.geo[ip] = data
                    save_cache(self.geo)
                    return json.dumps({"ok": True, "ip": ip, **data})
        except Exception:
            pass
        return json.dumps({"ok": False})

    def save_settings(self, s):
        incoming = json.loads(s) if isinstance(s, str) else s
        merged = dict(DEFAULT_SETTINGS)
        merged.update(self.settings)
        merged.update(incoming)
        panel_file = os.path.join(BASE_DIR, "panel_sizes.json")
        if os.path.exists(panel_file):
            try:
                with open(panel_file) as f:
                    merged["panel_sizes"] = json.load(f)
            except Exception:
                pass
        self.settings = merged
        save_settings_file(self.settings)
        self.alert_monitor.configure(
            self.settings.get('alert_dl_threshold', 0),
            self.settings.get('alert_ul_threshold', 0),
            self.settings.get('alert_cooldown', 30),
        )
        return json.dumps({"ok": True})

    def get_settings(self):
        return json.dumps(self.settings)

    def save_panel_sizes(self, data):
        try:
            d = json.loads(data) if isinstance(data, str) else data
            self.settings["panel_sizes"] = d
            save_settings_file(self.settings)
            panel_file = os.path.join(BASE_DIR, "panel_sizes.json")
            with open(panel_file, "w") as f:
                json.dump(d, f, indent=2)
            log(f"Panel sizes saved: {d}")
        except Exception as e:
            log(f"Panel save error: {e}")
        return json.dumps({"ok": True})

    def get_panel_sizes(self):
        panel_file = os.path.join(BASE_DIR, "panel_sizes.json")
        if os.path.exists(panel_file):
            try:
                with open(panel_file) as f:
                    return f.read()
            except Exception:
                pass
        return json.dumps(self.settings.get("panel_sizes", {}))

    def get_interfaces(self):
        ifaces = {}
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name, addr_list in addrs.items():
                if stats.get(name) and stats[name].isup:
                    ifaces[name] = {
                        "addrs": [a.address for a in addr_list if a.family in (socket.AF_INET, socket.AF_INET6)],
                        "speed": stats[name].speed,
                    }
        except Exception:
            pass
        return json.dumps(ifaces)

    def get_event_log(self):
        return json.dumps(self.event_log.get(200))

    def get_process_detail(self, pid):
        info = self.process_cache.get(int(pid))
        return json.dumps(info or {})

    def start_recording(self):
        self.session_recorder.start()
        return json.dumps(self.session_recorder.get_status())

    def stop_recording(self):
        self.session_recorder.stop()
        return json.dumps(self.session_recorder.get_status())

    def get_recording_status(self):
        return json.dumps(self.session_recorder.get_status())

    def run_speedtest(self):
        started = self.speed_tester.run_async()
        return json.dumps({"started": started})

    def get_speedtest_result(self):
        return json.dumps(self.speed_tester.get_result())

    def get_summaries(self, period='day'):
        return json.dumps(self.summary_tracker.get_period_summary(period))

    def get_app_usage(self):
        return json.dumps(self.summary_tracker.get_app_usage(20))

    def get_unknown_apps(self):
        return json.dumps(sorted(self.unknown_apps))

    def get_alerts(self):
        return json.dumps(self.alert_monitor.get_alerts())

    def generate_report(self):
        conns = self.tracker.get()
        conns_list = list(conns.values())
        io = psutil.net_io_counters()
        session_dur = time.time() - self.session_start

        proc_stats = Counter(c["proc"] for c in conns_list)
        svc_stats = Counter(c.get("service") or c.get("proc") or "Unknown" for c in conns_list)
        country_stats = Counter()
        for c in conns_list:
            g = self.geo.get(c["ip"], {})
            country_stats[g.get("country", "?") if isinstance(g, dict) else "?"] += 1

        report_data = {
            'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'session_duration': session_dur,
            'total_sent': io.bytes_sent,
            'total_recv': io.bytes_recv,
            'connection_count': len(conns_list),
            'top_processes': dict(proc_stats.most_common(15)),
            'top_services': dict(svc_stats.most_common(15)),
            'top_countries': dict(country_stats.most_common(15)),
            'app_usage': self.summary_tracker.get_app_usage(20),
            'alerts': self.alert_monitor.get_alerts(),
        }
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(REPORTS_DIR, f"report_{ts}.json")
        with open(path, 'w') as f:
            json.dump(report_data, f, indent=2)
        return json.dumps({'ok': True, 'path': path, 'data': report_data})

    def export_json(self):
        conns = self.tracker.get()
        conns_list = list(conns.values())
        io = psutil.net_io_counters()
        data = {
            'exported': datetime.now().isoformat(),
            'session': {
                'start': self.session_start,
                'duration': time.time() - self.session_start,
                'bytes_sent': io.bytes_sent,
                'bytes_recv': io.bytes_recv,
            },
            'connections': conns_list,
            'app_usage': self.summary_tracker.get_app_usage(50),
            'unknown_apps': sorted(self.unknown_apps),
        }
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(DATA_DIR, f"export_{ts}.json")
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return json.dumps({'ok': True, 'path': path})

    def get_summaries_list(self):
        files = []
        for f in sorted(os.listdir(RECORDINGS_DIR), reverse=True)[:20]:
            fp = os.path.join(RECORDINGS_DIR, f)
            files.append({'name': f, 'size': os.path.getsize(fp)})
        for f in sorted(os.listdir(REPORTS_DIR), reverse=True)[:20]:
            fp = os.path.join(REPORTS_DIR, f)
            files.append({'name': f, 'size': os.path.getsize(fp)})
        return json.dumps(files)

    def take_screenshot(self):
        return json.dumps({'ok': False, 'error': 'Use save_screenshot via JS'})

    def save_screenshot(self, data_url):
        try:
            import base64
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(REPORTS_DIR, f"screenshot_{ts}.png")
            header, encoded = data_url.split(",", 1)
            raw = base64.b64decode(encoded)
            with open(path, "wb") as f:
                f.write(raw)
            return json.dumps({'ok': True, 'path': path})
        except Exception as e:
            return json.dumps({'ok': False, 'error': str(e)})

    def ping_host(self, host):
        result = self.ping_monitor.ping(host)
        self.ping_monitor.track(host)
        return json.dumps(result)

    def get_ping_data(self):
        return json.dumps(self.ping_monitor.get())

    def scan_lan(self):
        self.lan_discovery.scan()
        return json.dumps({"started": True})

    def get_lan_devices(self):
        return json.dumps(self.lan_discovery.get())

    def traceroute(self, ip):
        now = time.time()
        if ip in self.trace_cache_time and now - self.trace_cache_time[ip] < 300:
            return json.dumps(self.trace_results.get(ip, {"hops": [], "status": "done"}))

        if self._trace_running:
            return json.dumps({"hops": [], "status": "running"})

        self._trace_running = True
        self.trace_results[ip] = {"hops": [], "status": "running"}
        threading.Thread(target=self._traceroute_worker, args=(ip,), daemon=True).start()
        return json.dumps({"hops": [], "status": "running"})

    def get_trace_result(self, ip):
        return json.dumps(self.trace_results.get(ip, {"hops": [], "status": "done"}))

    def trace_all(self):
        if self._trace_all_progress and self._trace_all_progress.get("status") == "running":
            return json.dumps(self._trace_all_progress)

        seen = set()
        ips = []
        for c in self.tracker.get().values():
            ip = c.get("ip")
            if ip and ip not in seen and ip != "0.0.0.0" and ip != "127.0.0.1":
                seen.add(ip)
                ips.append(ip)

        print(f"[TRACE ALL] Found {len(ips)} unique IPs to trace")
        if not ips:
            return json.dumps({"status": "done", "total": 0, "done": 0, "current": ""})

        self._trace_all_progress = {"status": "running", "total": len(ips), "done": 0, "current": ""}
        threading.Thread(target=self._trace_all_worker, args=(ips,), daemon=True).start()
        return json.dumps(self._trace_all_progress)

    def get_trace_all_status(self):
        if self._trace_all_progress:
            return json.dumps(self._trace_all_progress)
        return json.dumps({"status": "idle", "total": 0, "done": 0, "current": ""})

    def get_all_trace_results(self):
        return json.dumps(self.trace_results)

    def get_logs(self, since=0):
        return json.dumps(_log_capture.get(since))

    def _trace_all_worker(self, ips):
        try:
            for i, ip in enumerate(ips):
                self._trace_all_progress["current"] = ip
                self._trace_all_progress["done"] = i
                print(f"[TRACE ALL] {i+1}/{len(ips)} tracing {ip}")
                now = time.time()
                if ip not in self.trace_cache_time or now - self.trace_cache_time[ip] >= 300:
                    try:
                        self._do_traceroute(ip)
                    except Exception as e:
                        print(f"[TRACE ALL] Error tracing {ip}: {e}")
        except Exception as e:
            print(f"[TRACE ALL] Worker error: {e}")
        finally:
            self._trace_all_progress["done"] = len(ips)
            self._trace_all_progress["current"] = ""
            self._trace_all_progress["status"] = "done"
            print("[TRACE ALL] Done")

    def _traceroute_worker(self, ip):
        try:
            self._do_traceroute(ip)
        finally:
            self._trace_running = False

    def _do_traceroute(self, ip):
        hops = []
        try:
            out = subprocess.check_output(
                ["traceroute", "-n", "-w", "2", "-m", "15", ip],
                stderr=subprocess.DEVNULL, timeout=35
            ).decode("utf-8", errors="ignore")
            for line in out.strip().split("\n")[1:]:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                try:
                    hop_num = int(parts[0])
                except ValueError:
                    continue
                hop_ip = parts[1]
                if hop_ip == "*":
                    continue
                rtts = []
                for p in parts[2:]:
                    p = p.replace("ms", "")
                    if p == "*":
                        continue
                    try:
                        rtts.append(float(p))
                    except ValueError:
                        continue
                avg_rtt = sum(rtts) / len(rtts) if rtts else 0
                hops.append({"hop": hop_num, "ip": hop_ip, "rtt": round(avg_rtt, 2),
                             "lat": None, "lon": None, "city": "?", "country": "?"})
        except Exception:
            try:
                out = subprocess.check_output(
                    ["mtr", "-r", "-c", "1", "-n", ip],
                    stderr=subprocess.DEVNULL, timeout=35
                ).decode("utf-8", errors="ignore")
                for line in out.strip().split("\n")[1:]:
                    parts = line.strip().split()
                    if len(parts) < 5:
                        continue
                    try:
                        hop_num = int(parts[0].rstrip("."))
                    except ValueError:
                        continue
                    hop_ip = parts[1]
                    if hop_ip in ("???", "*"):
                        continue
                    try:
                        avg_rtt = float(parts[4])
                    except (ValueError, IndexError):
                        avg_rtt = 0
                    hops.append({"hop": hop_num, "ip": hop_ip, "rtt": round(avg_rtt, 2),
                                 "lat": None, "lon": None, "city": "?", "country": "?"})
            except Exception:
                pass

        unique_ips = list(set(h["ip"] for h in hops))
        geo_data = {}
        if unique_ips:
            try:
                for uip in unique_ips:
                    if uip in self.geo and isinstance(self.geo[uip], dict) and self.geo[uip].get("lat") is not None:
                        geo_data[uip] = self.geo[uip]
                uncached = [uip for uip in unique_ips if uip not in geo_data]
                if uncached:
                    payload = [{"query": uip, "fields": "status,country,city,lat,lon"} for uip in uncached]
                    r = requests.post("http://ip-api.com/batch", json=payload, timeout=10)
                    if r.status_code == 200:
                        results = r.json()
                        for uip, res in zip(uncached, results):
                            if res.get("status") == "success":
                                geo_data[uip] = {"lat": res["lat"], "lon": res["lon"],
                                                 "country": res.get("country", "?"), "city": res.get("city", "?")}
                            else:
                                geo_data[uip] = {"lat": None, "lon": None, "country": "?", "city": "?"}
            except Exception:
                pass

        for h in hops:
            gd = geo_data.get(h["ip"], {})
            if gd:
                h["lat"] = gd.get("lat")
                h["lon"] = gd.get("lon")
                h["city"] = gd.get("city", "?")
                h["country"] = gd.get("country", "?")

        result = {"hops": hops, "status": "done"}
        self.trace_results[ip] = result
        self.trace_cache_time[ip] = time.time()


# ----------------- MAIN -----------------
def main():
    sys.stdout = TeeWriter(sys.__stdout__, _log_capture)
    sys.stderr = TeeWriter(sys.__stderr__, _log_capture)
    _install_logging()
    _install_excepthook()
    log("Starting Network Traffic Monitor...")
    api = Api()
    html_path = os.path.join(BASE_DIR, "index.html")
    window = webview.create_window(
        "Network Traffic Monitor",
        url=f"file://{html_path}",
        js_api=api,
        width=1440, height=900,
        min_size=(1100, 700),
        text_select=False,
    )
    api.set_window(window)
    log("Window created, starting GUI...")
    webview.start(gui="gtk", debug=False)


if __name__ == "__main__":
    main()
