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
```
### 2️⃣ Install Dependencies
```bash
pip install scapy
```
### 🚀 Usage
```bash
Run the script with:
python ids_logger.py
```
### 🎯 Testing the IDS
Use Nmap from another machine to simulate an attack:
```bash
nmap -p 22 -sS <TARGET_IP>
```
The attacker's IP will be logged in suspicious_ips.log

### 📝 Sample Log Output
```bash
2025-02-13 10:15:30 - Possible SSH scan detected from 192.168.1.100
```

