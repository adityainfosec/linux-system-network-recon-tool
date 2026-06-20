import socket
import platform
import subprocess
import re
import json
import uuid
from datetime import datetime

print("=" * 60)
print(" UNIFIED SYSTEM + NETWORK RECON TOOL ")
print("=" * 60)

# ---------------- SYSTEM INFO ----------------
hostname = socket.gethostname()

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
except:
    local_ip = "Unknown"

mac = ":".join(("%012x" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))

print("\n--- SYSTEM INFO ---")
print("Hostname:", hostname)
print("Local IP:", local_ip)
print("MAC Address:", mac)
print("OS:", platform.system())
print("Kernel:", platform.release())
print("Architecture:", platform.machine())

# ---------------- NETWORK INTERFACES ----------------
print("\n--- NETWORK INTERFACES ---")
try:
    interfaces = subprocess.check_output("ip a", shell=True).decode()
    print(interfaces)
except:
    print("Unable to fetch interfaces")

# ---------------- LAN DEVICE SCAN ----------------
print("\n--- LAN DEVICE SCAN ---")

try:
    output = subprocess.check_output("ip neigh", shell=True).decode()
except:
    output = ""

devices = []

for line in output.split("\n"):
    parts = re.split(r"\s+", line)
    if len(parts) >= 5:
        devices.append({
            "ip": parts[0],
            "mac": parts[4],
            "state": parts[5] if len(parts) > 5 else "UNKNOWN"
        })

if devices:
    print(f"{'IP Address':<18} {'MAC Address':<20} {'State'}")
    print("-" * 60)

    for d in devices:
        print(f"{d['ip']:<18} {d['mac']:<20} {d['state']}")
else:
    print("No devices found")

# ---------------- REPORT FILE ----------------
report = {
    "hostname": hostname,
    "local_ip": local_ip,
    "mac": mac,
    "scan_time": str(datetime.now()),
    "devices": devices
}

with open("recon_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("\nReport saved -> recon_report.json")
print("=" * 60)