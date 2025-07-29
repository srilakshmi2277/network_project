# ELEVATE LABS - PROJECT
# Network Packet Sniffer with Alert System

A real-time network traffic analyzer with anomaly detection capabilities. This tool captures network packets, detects security threats like port scanning and flooding attacks, and provides comprehensive analysis through both CLI and visualization tools.

##  Features

- **Real-time Packet Capture**: Capture and analyze network traffic using Scapy
- **Anomaly Detection**: Automatically detect port scanning and flooding attacks
- **SQLite Database Storage**: Persistent storage of packet data and security alerts
- **CLI Analysis Tools**: Comprehensive command-line interface for traffic analysis
- **Email Alerting**: Send email notifications for critical security events
- **Simulation Mode**: Test the system without requiring root privileges

##  Requirements

- Python 3.7+
- Root privileges (for real packet capture)
- Required Python packages (see requirements.txt):
  - scapy >= 2.5.0
  - matplotlib >= 3.8.0
  - sqlite3 (built-in)
  - smtplib (built-in)

## 🛠️ Installation

1. Install Python dependencies:
```bash
pip install scapy matplotlib
```

2. Make scripts executable:
```bash
chmod +x packet_sniffer.py
chmod +x packet_analyzer.py
chmod +x demo_sniffer.py
```

##  Quick Start

### 1. Demo Mode (No Root Required)
Run the demo to see the system in action with simulated data:

```bash
python demo_sniffer.py
```

This generates realistic network traffic with security events for testing.

### 2. Real Packet Capture (Requires Root)
Capture real network traffic:

```bash
sudo python packet_sniffer.py
```

### 3. Simulation Mode
Test without root privileges:

```bash
python packet_sniffer.py --simulate
```

##  Analysis Tools

### Traffic Analysis
```bash
# Show traffic summary for last hour
python packet_analyzer.py --traffic 1

# Show traffic summary for last 24 hours
python packet_analyzer.py --traffic 24
```

### Security Alert Analysis
```bash
# Show security alerts for last 24 hours
python packet_analyzer.py --alerts 24

# Show only recent alerts
python packet_analyzer.py --alerts 1
```

### Generate Visualizations
```bash
# Create traffic plot for last hour
python packet_analyzer.py --plot 1

# Generate plot for last 6 hours
python packet_analyzer.py --plot 6
```

### Live Monitoring Dashboard
```bash
# Start live monitoring (refreshes every 30 seconds)
python packet_analyzer.py --live
```

##  Command-Line Options

### packet_sniffer.py
```bash
Usage: packet_sniffer.py [OPTIONS]

Options:
  -i, --interface TEXT    Network interface to capture on
  -f, --filter TEXT       BPF filter string (e.g., "tcp port 80")
  --simulate             Run in simulation mode (no root required)
  --stats                Show database statistics
  --alerts               Show recent alerts
```

### packet_analyzer.py
```bash
Usage: packet_analyzer.py [OPTIONS]

Options:
  --traffic INTEGER      Show traffic summary for last N hours (default: 1)
  --alerts INTEGER       Show alert summary for last N hours (default: 24)
  --plot INTEGER         Generate traffic plot for last N hours
  --db TEXT             Database file path (default: packets.db)
  --live                Start live monitoring dashboard
```

##  Security Features

### Anomaly Detection

**Port Scanning Detection:**
- Monitors connections to multiple ports from single IP
- Threshold: 10 different ports in 60 seconds
- Alert Level: HIGH

**Flood Attack Detection:**
- Detects high packet rates from single source
- Threshold: 100 packets in 10 seconds  
- Alert Level: CRITICAL

### Alert System

All security events are:
- Logged to SQLite database with timestamps
- Displayed in CLI output with severity levels
- Available for email notification (configurable)

##  Database Schema

### Packets Table
```sql
CREATE TABLE packets (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    packet_size INTEGER,
    flags TEXT,
    raw_data TEXT
);
```

### Alerts Table
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    alert_type TEXT,
    severity TEXT,
    description TEXT,
    src_ip TEXT,
    details TEXT
);
```

##  Sample Output

### Traffic Summary
```
======================================================================
NETWORK TRAFFIC SUMMARY - Last 1 hour(s)
======================================================================
Total Packets:        314
Unique Source IPs:    5
Unique Dest IPs:      8
Avg Packet Size:      907.38 bytes

Protocol Distribution:
  TCP   :      268 packets ( 85.4%)
  UDP   :       46 packets ( 14.6%)

Top Talkers (by packet count):
   1. 203.0.113.10    - 101 packets
   2. 192.168.1.20    - 67 packets
   3. 192.168.1.10    - 67 packets
```

### Security Alerts
```
======================================================================
SECURITY ALERT SUMMARY - Last 24 hour(s)
======================================================================
Alert Statistics:
Total Alerts: 6
  PORT_SCAN       (HIGH    ):   5 alerts
  FLOOD_ATTACK    (CRITICAL):   1 alerts

Top Attacking IPs:
   1. 192.168.1.100   - 5 alerts
   2. 203.0.113.10    - 1 alerts
```

##  Email Alerting (Optional)

Configure email alerts by modifying the EmailAlerter class in `packet_analyzer.py`:

```python
alerter = EmailAlerter(
    smtp_server='smtp.gmail.com',
    smtp_port=587,
    username='your-email@gmail.com',
    password='your-app-password',
    sender_email='alerts@yourcompany.com'
)
```

##  Usage Examples

### Basic Network Monitoring
```bash
# Start packet sniffer on specific interface
sudo python packet_sniffer.py -i eth0

# Filter for HTTP traffic only
sudo python packet_sniffer.py -f "tcp port 80"

# Monitor and generate hourly reports
python packet_analyzer.py --traffic 1 --alerts 1 --plot 1
```

### Security Monitoring
```bash
# Check for recent security events
python packet_sniffer.py --alerts

# Generate comprehensive security report
python packet_analyzer.py --alerts 24

# Live security monitoring
python packet_analyzer.py --live
```

## 🔍 Troubleshooting

### Permission Denied Errors
- Packet capture requires root privileges
- Use `sudo` when capturing real traffic
- Use `--simulate` mode for testing without root

### Scapy Installation Issues
```bash
# Ubuntu/Debian
sudo apt-get install python3-scapy

# Or via pip
pip install scapy
```

### Database Issues
- Database is created automatically on first run
- Default location: `packets.db` in current directory
- Use `--db` option to specify different location

## 🏗️ Architecture

```
packet_sniffer.py       # Main packet capture engine
├── PacketDatabase      # SQLite database handler
├── AnomalyDetector     # Security threat detection
└── PacketSniffer       # Core sniffer class

packet_analyzer.py      # Analysis and visualization
├── PacketAnalyzer      # Traffic analysis engine
├── EmailAlerter        # Email notification system
└── CLI Interface       # Command-line tools

demo_sniffer.py         # Demo and testing
├── generate_port_scan_attack()
├── generate_flood_attack()
└── generate_normal_traffic()
```
