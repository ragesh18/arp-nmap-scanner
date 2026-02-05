# **Technical Documentation: arp-nmap-scanner**
*A Python-based Network Reconnaissance Tool*

---

## **1. Introduction**
The **arp-nmap-scanner** is a Python-based network reconnaissance tool that performs **ARP-based host discovery**, **targeted TCP port scanning**, and **service/version detection** using **Scapy** and **Nmap**. It is designed for **internal network assessments**, offering **multi-threaded scanning** for efficiency.

### **Key Features**
| Feature | Description |
|---------|-------------|
| **Layer 2 Host Discovery** | Uses ARP scanning to identify live hosts (IP, MAC, hostname). |
| **Targeted Port Scanning** | Scans only the **top N TCP ports** (avoids full-range scans). |
| **Service & Version Detection** | Identifies running services and versions using Nmap. |
| **Multi-threaded Scanning** | Faster host discovery via threading. |
| **Modular Design** | Easy to extend (e.g., OS detection, reporting). |

---

## **2. Architecture Overview**
The tool follows a **modular, pipeline-based workflow**:

```
CIDR Input → ARP Scan → Host Deduplication → Top Port Scan → Service Detection
```

### **Core Components**
1. **ARP Scanner (`scan()`)**
   - Uses **Scapy** to send ARP requests and capture responses.
   - Extracts **IP, MAC, and hostname** from replies.
   - Runs in **multi-threaded mode** for efficiency.

2. **Port Scanner (`scan_top_ports()`)**
   - Uses **Nmap3** (`nmap3.NmapScanTechniques`) to scan **top N ports** per host.
   - Filters only **open ports** and stores results.

3. **Service Detector (`detect_services()`)**
   - Uses **Nmap’s version detection** (`nmap3.Nmap`) to identify services.
   - Captures **banner grabbing** and version info.

4. **Result Handler (`print_result()`)**
   - Formats and displays results in a structured table.

---

## **3. Setup & Installation**

### **Prerequisites**
- **Python 3.6+**
- **Root/Sudo privileges** (required for ARP scanning)
- **Nmap** (installed via system package manager)

### **Dependencies**
Install required Python packages:
```bash
pip install scapy python-nmap nmap3
```

### **Nmap Installation (Linux)**
```bash
sudo apt install nmap  # Debian/Ubuntu
sudo yum install nmap  # RHEL/CentOS
```

---

## **4. Configuration**
### **Environment Variables (Optional)**
| Variable | Description | Default |
|----------|-------------|---------|
| `TOP_N_PORTS` | Number of top ports to scan | `100` |
| `SCAN_TIMEOUT` | ARP scan timeout (seconds) | `1` |

### **Example `.env` File**
```ini
TOP_N_PORTS=200
SCAN_TIMEOUT=2
```

---

## **5. Usage & CLI Interface**
### **Running the Scanner**
```bash
sudo python3 network_scan.py
```
**Input Prompt:**
```
Enter a valid CIDR range (e.g., 192.168.1.0/24):
```

### **Sample Output**
```
IP                    MAC                    Hostname
--------------------------------------------------------------------------------
192.168.1.1           bc:62:d2:cf:d8:48       router
192.168.1.10          3c:52:82:ab:91:22       kal
192.168.1.20          00:1a:2b:3c:4d:5e       Unknown
```

### **Port & Service Scan Output**
```json
{
  "192.168.1.1": [
    {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache/2.4.41"}
  ],
  "192.168.1.10": [
    {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2p1"}
  ]
}
```

---

## **6. Code Documentation (Function Breakdown)**

### **1. `scan(ip, result_queue)`**
- **Purpose:** Performs ARP scan on a given IP range.
- **Parameters:**
  - `ip` (str): Target IP (e.g., `192.168.1.0/24`).
  - `result_queue` (Queue): Stores scan results.
- **Returns:** Hosts with **IP, MAC, and hostname**.
- **Key Logic:**
  - Constructs **ARP request** (`scapy.ARP`).
  - Sends **broadcast packet** (`scapy.Ether`).
  - Captures responses (`scapy.srp`).
  - Resolves hostnames (`socket.gethostbyaddr`).

### **2. `print_result(result)`**
- **Purpose:** Formats and prints scan results.
- **Parameters:**
  - `result` (list): List of host dictionaries.
- **Output Format:**
  ```
  IP       MAC       Hostname
  ------------------------------------------------
  192.168.1.1  bc:62:d2:cf:d8:48  router
  ```

### **3. `scan_top_ports(hosts, top_n=100)`**
- **Purpose:** Scans **top N ports** per host using Nmap.
- **Parameters:**
  - `hosts` (list): List of discovered hosts.
  - `top_n` (int): Number of ports to scan (default: `100`).
- **Returns:** Dictionary of `{IP: [ports]}`.
- **Key Logic:**
  - Uses `nmap3.NmapScanTechniques` for **fast scanning**.
  - Filters only **open ports** (`state == 'open'`).

### **4. `detect_services(ip, ports)`**
- **Purpose:** Detects **services & versions** on open ports.
- **Parameters:**
  - `ip` (str): Target IP.
  - `ports` (list): List of open ports.
- **Returns:** List of service dictionaries.
- **Key Logic:**
  - Uses `nmap3.Nmap` for **version detection**.
  - Constructs Nmap command: `--version-all -p {port_range}`.

---

## **7. Error Handling & Edge Cases**
| Scenario | Handling |
|----------|----------|
| **ARP Timeout** | Retries with increased timeout. |
| **Hostname Resolution Failure** | Falls back to `"Unknown"`. |
| **Nmap Not Found** | Checks system path (`os.system("which nmap")`). |
| **Invalid CIDR** | Validates input using `ipaddress.ip_network`. |

---

## **8. Performance Optimization**
| Technique | Benefit |
|-----------|---------|
| **Multi-threading** | Faster host discovery (`ThreadPoolExecutor`). |
| **Targeted Port Scanning** | Avoids full-range scans (`--top-ports`). |
| **Nmap Aggressive Mode (`-T4`)** | Speeds up port scanning. |
| **Queue-based Result Handling** | Efficiently processes large networks. |

---

## **9. Extensibility**
### **Possible Enhancements**
| Feature | Implementation |
|---------|----------------|
| **OS Detection** | Use `nmap3.Nmap().nmap_os_detection()`. |
| **MITRE ATT&CK Mapping** | Integrate with `pyattck`. |
| **Export to CSV/JSON** | Add `json.dump()` or `pandas.DataFrame`. |
| **GUI Interface** | Use `tkinter` or `PyQt`. |

---

## **10. Security Considerations**
- **Run as Root:** ARP scanning requires elevated privileges.
- **Rate Limiting:** Avoid overwhelming networks.
- **Logging:** Log scan results for auditing.
- **Nmap Safety:** Use `--reason` to avoid false positives.

---

## **11. Deployment Instructions**
### **Docker Deployment (Optional)**
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install scapy python-nmap nmap3
CMD ["python3", "network_scan.py"]
```
**Build & Run:**
```bash
docker build -t arp-nmap-scanner .
docker run --privileged -it arp-nmap-scanner
```

---

## **12. Troubleshooting**
| Issue | Solution |
|-------|----------|
| **ARP Scan Fails** | Check if interface is in promiscuous mode (`ifconfig`). |
| **Nmap Not Found** | Ensure `nmap` is in `PATH` or use `sudo`. |
| **Slow Performance** | Increase `TOP_N_PORTS` or reduce scan timeout. |
| **Permission Denied** | Run with `sudo` or adjust `capabilities`. |

---

## **13. License & Attribution**
- **License:** MIT (check `LICENSE` file).
- **Dependencies:**
  - Scapy ([https://scapy.net/](https://scapy.net/))
  - Nmap3 ([https://github.com/savonet/nmap3](https://github.com/savonet/nmap3))

---

## **14. Future Roadmap**
| Feature | Status |
|---------|--------|
| **Active Directory Integration** | Planned |
| **Automated Report Generation** | In Progress |
| **Cloud-Based Scanning** | Research |

---
**Documentation Last Updated:** `[Insert Date]`
**Maintainer:** `[Your Name/Team]`
