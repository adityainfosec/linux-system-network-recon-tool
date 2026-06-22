# 🖥️ Linux System Network Recon Tool

A professional Python-based Linux reconnaissance tool designed to collect detailed system, hardware, and network information for cybersecurity learning, system administration, and authorized security assessments.

The tool gathers host information, enumerates network interfaces, discovers LAN devices, and generates detailed JSON and CSV reports.

---

# 📌 Features

## 🖥️ System Information

- Hostname Detection
- Current Username
- Local IP Address
- Public IP Address (when available)
- MAC Address
- Operating System
- Linux Distribution
- Kernel Version
- System Architecture
- Python Version
- Current Date & Time
- System Uptime

---

## 💻 Hardware Information

- CPU Model
- Physical CPU Cores
- Logical CPU Cores
- CPU Usage
- RAM Usage
- Disk Usage

---

## 🌐 Network Information

- Network Interface Enumeration
- IPv4 & IPv6 Addresses
- Default Gateway Detection
- DNS Server Detection
- ARP Table Enumeration
- Connected LAN Device Discovery
- MAC Address Enumeration
- Interface Status

---

## 📄 Report Generation

- JSON Report
- CSV Report
- Timestamped Reports
- Automatic Reports Directory Creation

---

## 🎨 CLI Features

- Colored Terminal Output
- Professional Console Layout
- Error Handling
- Progress Messages
- Scan Summary

---

# ⚙️ Requirements

- Python 3.9+
- Linux Operating System
- psutil

---

# 📦 Installation

```bash
git clone https://github.com/adityainfosec/linux-system-network-recon-tool.git

cd linux-system-network-recon-tool

pip install psutil
```

---

# 🚀 Usage

Run the tool:

```bash
python3 recon_tool.py
```

Enable verbose mode:

```bash
python3 recon_tool.py --verbose
```

Save report to custom location:

```bash
python3 recon_tool.py --output reports/my_report.json
```

Display version:

```bash
python3 recon_tool.py --version
```

---

# 📊 Example Output

```
============================================================
Linux System Network Recon Tool v2.0
============================================================

Hostname          : kali
Username          : aditya
Operating System  : Linux
Distribution      : Kali GNU/Linux
Kernel Version    : 6.x.x
Architecture      : x86_64

Local IP          : 192.168.1.12
Public IP         : xxx.xxx.xxx.xxx
MAC Address       : 08:00:27:AA:BB:CC

CPU Usage         : 12%
RAM Usage         : 41%
Disk Usage        : 58%

Network Interfaces
------------------
eth0
wlan0
lo

Connected LAN Devices
---------------------
192.168.1.1
192.168.1.10
192.168.1.15

JSON Report Saved
CSV Report Saved

Reconnaissance Complete
```

---

# 🧠 How It Works

1. Collects Linux system information.
2. Retrieves hardware statistics.
3. Enumerates available network interfaces.
4. Detects gateway and DNS configuration.
5. Discovers LAN devices using the ARP cache.
6. Displays the collected information in a clean CLI interface.
7. Generates JSON and CSV reports for future analysis.

---

# 🛠️ Technologies Used

- Python 3
- Socket Programming
- Platform Module
- subprocess
- psutil
- ipaddress
- pathlib
- JSON
- CSV
- Linux Networking Utilities

---

# 📂 Project Structure

```
linux-system-network-recon-tool/
│
├── recon_tool.py
├── reports/
├── README.md
├── LICENSE
└── .gitignore
```

---

# 🔮 Future Improvements

- Network Port Scanner
- Ping Sweep
- Reverse DNS Lookup
- Service Detection
- Export to HTML
- PDF Report Generation
- Live Network Monitoring
- Whois Lookup
- GeoIP Lookup
- Docker Environment Detection

---

# ⚠️ Disclaimer

This project is intended for educational purposes and authorized security testing only.

Only use this tool on systems and networks where you have explicit permission.

The author is not responsible for any misuse of this software.

---

# 👨‍💻 Author

**Aditya Gupta**

Cybersecurity Enthusiast | Python Security Tools Developer | Blue Team | Network Security

GitHub:
https://github.com/adityainfosec

---

# 📜 License

This project is licensed under the MIT License.
