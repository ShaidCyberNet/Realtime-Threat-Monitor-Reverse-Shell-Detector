import json
import time
import subprocess
import requests
import glob
import re
from collections import defaultdict, Counter
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.live import Live
from rich.table import Table
from rich.console import Console
from scapy.all import sniff, Raw, IP, TCP

ALERTS_DIR = "alerts"
BAN_THRESHOLD = 15
WHITELIST = {"192.168.0.1", "127.0.0.1"}  # Trusted IPs here
BAD_COUNTRIES = {"russia", "china", "north korea", "iran"}

console = Console()
alerts = defaultdict(list)
ip_hits = Counter()
country_scores = Counter()
seen_ips = set()
geo_cache = {}

TRIAGE_CODES = {
    "NEW": "NEW",
    "IN_PROGRESS": "INP",
    "ESCALATE": "ESC",
    "MONITOR": "MON",
    "BAN": "BAN",
}

REVERSE_SHELL_PATTERNS = [
    r"bash\s+-i",
    r"nc\s+-e",
    r"sh\s+-i",
    r"python\s+-c",
    r"perl\s+-e",
    r"php\s+-r",
    r"curl\s+http",
    r"wget\s+http",
    r"exec\s+/bin/sh",
]

def geo_lookup(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        resp.raise_for_status()
        data = resp.json()
        country = data.get("country", "Unknown").lower()
        city = data.get("city", "-")
        isp = data.get("isp", "-")
        geo_cache[ip] = (country, city, isp)
        return country, city, isp
    except:
        geo_cache[ip] = ("unknown", "-", "-")
        return "unknown", "-", "-"

def ban_ip(ip):
    if ip in WHITELIST:
        return
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    try:
        subprocess.run(cmd, shell=True, check=True)
        console.print(f"[BANNED] {ip}", style="bold red")
    except subprocess.CalledProcessError as e:
        console.print(f"[ERROR] Ban failed for {ip}: {e}", style="red")

def triage_alert(alert, country):
    sev = alert.get("severity", 0)
    alert_type = alert.get("alert_type", "").upper()

    if country in BAD_COUNTRIES and sev >= 7:
        return TRIAGE_CODES["ESCALATE"]
    if "MALWARE" in alert_type or "RANSOMWARE" in alert_type:
        return TRIAGE_CODES["IN_PROGRESS"]
    if sev >= 5:
        return TRIAGE_CODES["MONITOR"]
    return TRIAGE_CODES["NEW"]

def update_scores(ip, alert):
    ip_hits[ip] += 1

    country, _, _ = geo_lookup(ip)
    if country in BAD_COUNTRIES:
        country_scores[country] += 5

    score = ip_hits[ip] + country_scores[country]

    if score >= BAN_THRESHOLD:
        ban_ip(ip)
        return TRIAGE_CODES["BAN"]
    return None

def packet_sniffer():
    def process_packet(pkt):
        if not (pkt.haslayer(Raw) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        payload = pkt[Raw].load.decode(errors="ignore")
        src_ip = pkt[IP].src

        for pattern in REVERSE_SHELL_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                if src_ip in seen_ips:
                    return
                seen_ips.add(src_ip)
                ip_hits[src_ip] += 1
                alert = {
                    "alert_type": "ReverseShellPattern",
                    "severity": 8,
                    "message": f"Reverse shell payload detected: {pattern}"
                }
                alerts[src_ip].append(alert)
                console.print(f"[REVERSE SHELL] Payload from {src_ip}: {pattern}", style="bold red")
                triage = update_scores(src_ip, alert)
                if triage == TRIAGE_CODES["BAN"]:
                    console.print(f"[AUTO BAN] {src_ip} banned due to reverse shell pattern", style="red")

    sniff_thread = Thread(target=lambda: sniff(iface="lo", prn=process_packet, store=False), daemon=True)
    sniff_thread.start()

class AlertHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        self.process_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        self.process_file(event.src_path)

    def process_file(self, filepath):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            ip = data.get("ip")
            if not ip:
                with open(filepath) as f2:
                    content = f2.read()
                    match = re.search(r"(\d{1,3}\.){3}\d{1,3}", content)
                    if match:
                        ip = match.group()
                    else:
                        console.print(f"[WARN] No IP found in {filepath}", style="yellow")
                        return
            alerts[ip].append(data)
            seen_ips.add(ip)
            triage = update_scores(ip, data)
            if triage == TRIAGE_CODES["BAN"]:
                console.print(f"[AUTO BAN] {ip} banned due to high score.", style="red")
            else:
                console.print(f"[INFO] Processed alert for {ip}", style="green")
        except Exception as e:
            console.print(f"[ERROR] Failed processing {filepath}: {e}", style="red")

def build_dashboard():
    table = Table(title="Realtime Threat Monitor + Reverse Shell Detector", style="cyan")
    table.add_column("IP", style="green")
    table.add_column("Hits", justify="right", style="yellow")
    table.add_column("Country", style="magenta")
    table.add_column("City", style="blue")
    table.add_column("ISP", style="blue")
    table.add_column("Severity", justify="right", style="red")
    table.add_column("Alert Type", style="red")
    table.add_column("Triage", style="yellow")
    table.add_column("Score", justify="right", style="red")

    for ip in sorted(ip_hits, key=ip_hits.get, reverse=True):
        if ip in WHITELIST:
            continue
        country, city, isp = geo_lookup(ip)
        alert = alerts[ip][-1] if alerts[ip] else {}
        triage = triage_alert(alert, country)
        score = ip_hits[ip] + country_scores[country]
        table.add_row(
            ip,
            str(ip_hits[ip]),
            country.title(),
            city,
            isp,
            str(alert.get("severity", 0)),
            alert.get("alert_type", "UNKNOWN"),
            triage,
            str(score),
        )
    return table

def start_watcher():
    observer = Observer()
    handler = AlertHandler()
    observer.schedule(handler, path=ALERTS_DIR, recursive=False)
    observer.start()
    return observer

if __name__ == "__main__":
    if not glob.glob(f"{ALERTS_DIR}/*.json"):
        console.print(f"[WARN] No alert files found in '{ALERTS_DIR}'. Place JSON alerts here.", style="yellow")

    observer = start_watcher()
    packet_sniffer()

    try:
        with Live(build_dashboard(), refresh_per_second=2, console=console) as live:
            while True:
                time.sleep(1)
                live.update(build_dashboard())
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

