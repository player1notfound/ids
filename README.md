# 🚀 Intrusion Detection System (IDS) with Logging

This Python script monitors network traffic and logs **suspicious IPs** attempting unauthorized access (e.g., SSH scans on port 22).

## 📌 Features
✅ Detects suspicious network activity  
✅ Logs malicious IPs to `suspicious_ips.log`  
✅ Avoids duplicate logs for the same attacker  
✅ Uses **Scapy** for network sniffing  

## 🛠️ Installation
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/ids-logger.git
cd ids-logger
