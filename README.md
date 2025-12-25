# arp-nmap-scanner
A Python-based network reconnaissance tool that performs ARP-based host discovery, targeted TCP port scanning, and service/version detection using Scapy and Nmap.



---

## 🔍 Features

- **Layer 2 Host Discovery**
  - Uses ARP scanning to accurately identify live hosts
  - Collects IP address, MAC address, and hostname

- **Targeted Port Scanning**
  - Scans only the **top N TCP ports** on discovered live hosts
  - Avoids noisy full-range scans

- **Service & Version Detection**
  - Identifies running services and versions using Nmap
  - Captures banners when available

- **Multi-threaded Scanning**
  - Faster host discovery using threading
  - Efficient for medium-sized internal networks

- **Clean & Modular Design**
  - Easy to extend with OS detection, reporting, or MITRE ATT&CK mapping

---

## 🛠️ Technologies Used

- **Python 3**
- **Scapy** – ARP-based network discovery
- **Nmap (via nmap3)** – Port scanning and service detection
- **Threading / Queues** – Concurrent scanning
- **ipaddress** – CIDR handling

---

## 📌 Workflow

```
CIDR Input
   ↓
ARP Scan (Live Host Discovery)
   ↓
Deduplication of Hosts
   ↓
Top TCP Port Scan (per host)
   ↓
Service & Version Detection
```
---

## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/your-username/network-recon-tool.git
cd network-recon-tool
```

### 2️⃣ Install dependencies

```bash
pip install scapy python-nmap nmap3
```

### 3️⃣ Ensure Nmap is installed
```bash
sudo apt install nmap
```
---
### ▶️ Usage

Run the script with sudo/root privileges (required for ARP scanning):
```bash
sudo python3 network_scan.py
```
**Enter a valid CIDR range:**

***Enter network ip address: 192.168.1.0/24***
---

### 📤 Sample Output
```text
IP                    MAC                    Hostname
--------------------------------------------------------------------------------
192.168.1.1            bc:62:d2:cf:d8:48     router
192.168.1.10           3c:52:82:ab:91:22     kali

Open Ports:

Host: 192.168.1.10
  Port 22/tcp OPEN
  Port 80/tcp OPEN
--------------------------------------------------
  Detected Services:
    Port 22: ssh - 8.4 (OpenSSH)
    Banner: OpenSSH 8.4
==================================================
```
