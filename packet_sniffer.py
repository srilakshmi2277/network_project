#!/usr/bin/env python3
"""
Network Packet Sniffer with Alert System
Real-time network traffic analysis with anomaly detection
"""

import logging
import sqlite3
import threading
import time
import signal
import sys
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set
import argparse
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.animation import FuncAnimation

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    print("WARNING: Scapy not available. Install with: pip install scapy")
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('packet_sniffer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PacketDatabase:
    """SQLite database handler for packet storage"""
    
    def __init__(self, db_path: str = "packets.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                flags TEXT,
                raw_data TEXT
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                alert_type TEXT,
                severity TEXT,
                description TEXT,
                src_ip TEXT,
                details TEXT
            )
        ''')
        
        # Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                total_packets INTEGER,
                tcp_packets INTEGER,
                udp_packets INTEGER,
                icmp_packets INTEGER,
                unique_ips INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def insert_packet(self, packet_data: Dict):
        """Insert packet data into database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, 
                               protocol, packet_size, flags, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data['timestamp'],
            packet_data['src_ip'],
            packet_data['dst_ip'],
            packet_data.get('src_port'),
            packet_data.get('dst_port'),
            packet_data['protocol'],
            packet_data['packet_size'],
            packet_data.get('flags'),
            packet_data.get('raw_data', '')
        ))
        
        conn.commit()
        conn.close()
    
    def insert_alert(self, alert_data: Dict):
        """Insert alert into database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, severity, description, src_ip, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert_data['timestamp'],
            alert_data['alert_type'],
            alert_data['severity'],
            alert_data['description'],
            alert_data.get('src_ip'),
            json.dumps(alert_data.get('details', {}))
        ))
        
        conn.commit()
        conn.close()
        logger.warning(f"ALERT: {alert_data['alert_type']} - {alert_data['description']}")
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get recent packets from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM packets 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        packets = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return packets
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return alerts

class AnomalyDetector:
    """Detect network anomalies and security threats"""
    
    def __init__(self):
        self.connection_tracker = defaultdict(set)  # IP -> set of ports
        self.packet_rates = defaultdict(deque)  # IP -> packet timestamps
        self.port_scan_threshold = 10  # ports in 60 seconds
        self.flood_threshold = 100  # packets in 10 seconds
        self.time_window = 60  # seconds
        
    def detect_port_scan(self, src_ip: str, dst_port: int) -> Optional[Dict]:
        """Detect potential port scanning activity"""
        current_time = datetime.now()
        
        # Add port to connection tracker
        self.connection_tracker[src_ip].add(dst_port)
        
        # Clean old entries (older than time_window)
        # This is simplified - in production you'd want more sophisticated tracking
        
        if len(self.connection_tracker[src_ip]) > self.port_scan_threshold:
            return {
                'timestamp': current_time,
                'alert_type': 'PORT_SCAN',
                'severity': 'HIGH',
                'description': f'Potential port scan detected from {src_ip}',
                'src_ip': src_ip,
                'details': {
                    'ports_accessed': list(self.connection_tracker[src_ip]),
                    'port_count': len(self.connection_tracker[src_ip])
                }
            }
        return None
    
    def detect_flood(self, src_ip: str) -> Optional[Dict]:
        """Detect potential flooding/DDoS activity"""
        current_time = datetime.now()
        
        # Add current packet to rate tracker
        self.packet_rates[src_ip].append(current_time)
        
        # Remove old entries
        cutoff_time = current_time - timedelta(seconds=10)
        while (self.packet_rates[src_ip] and 
               self.packet_rates[src_ip][0] < cutoff_time):
            self.packet_rates[src_ip].popleft()
        
        # Check if rate exceeds threshold
        if len(self.packet_rates[src_ip]) > self.flood_threshold:
            return {
                'timestamp': current_time,
                'alert_type': 'FLOOD_ATTACK',
                'severity': 'CRITICAL',
                'description': f'Potential flood attack detected from {src_ip}',
                'src_ip': src_ip,
                'details': {
                    'packet_rate': len(self.packet_rates[src_ip]),
                    'time_window': '10 seconds'
                }
            }
        return None

class PacketSniffer:
    """Main packet sniffer class"""
    
    def __init__(self, interface: str = None, filter_str: str = None):
        self.interface = interface
        self.filter_str = filter_str
        self.db = PacketDatabase()
        self.detector = AnomalyDetector()
        self.running = False
        self.packet_count = 0
        self.start_time = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'unique_ips': set()
        }
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\nShutting down packet sniffer...")
        self.stop()
        sys.exit(0)
    
    def process_packet(self, packet):
        """Process captured packet"""
        try:
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            current_time = datetime.now()
            
            # Extract basic packet information
            packet_data = {
                'timestamp': current_time,
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'packet_size': len(packet),
                'raw_data': str(packet.summary())
            }
            
            # Update statistics
            self.stats['total_packets'] += 1
            self.stats['unique_ips'].add(ip_layer.src)
            self.stats['unique_ips'].add(ip_layer.dst)
            
            # Protocol-specific processing
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_data.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': str(tcp_layer.flags),
                    'protocol': 'TCP'
                })
                self.stats['tcp_packets'] += 1
                
                # Check for port scan
                alert = self.detector.detect_port_scan(ip_layer.src, tcp_layer.dport)
                if alert:
                    self.db.insert_alert(alert)
            
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_data.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'protocol': 'UDP'
                })
                self.stats['udp_packets'] += 1
            
            elif packet.haslayer(ICMP):
                packet_data['protocol'] = 'ICMP'
                self.stats['icmp_packets'] += 1
            
            # Check for flood attacks
            flood_alert = self.detector.detect_flood(ip_layer.src)
            if flood_alert:
                self.db.insert_alert(flood_alert)
            
            # Store packet in database
            self.db.insert_packet(packet_data)
            
            self.packet_count += 1
            
            # Print packet info (CLI output)
            if self.packet_count % 10 == 0:  # Print every 10th packet
                self.print_packet_summary(packet_data)
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def print_packet_summary(self, packet_data):
        """Print packet summary to console"""
        protocol = packet_data.get('protocol', 'Unknown')
        src_info = f"{packet_data['src_ip']}"
        dst_info = f"{packet_data['dst_ip']}"
        
        if packet_data.get('src_port'):
            src_info += f":{packet_data['src_port']}"
        if packet_data.get('dst_port'):
            dst_info += f":{packet_data['dst_port']}"
        
        print(f"[{packet_data['timestamp'].strftime('%H:%M:%S')}] "
              f"{protocol} {src_info} -> {dst_info} "
              f"({packet_data['packet_size']} bytes)")
    
    def print_statistics(self):
        """Print current statistics"""
        if self.start_time:
            duration = datetime.now() - self.start_time
            pps = self.stats['total_packets'] / max(duration.total_seconds(), 1)
        else:
            pps = 0
        
        print("\n" + "="*60)
        print("PACKET SNIFFER STATISTICS")
        print("="*60)
        print(f"Total Packets:     {self.stats['total_packets']}")
        print(f"TCP Packets:       {self.stats['tcp_packets']}")
        print(f"UDP Packets:       {self.stats['udp_packets']}")
        print(f"ICMP Packets:      {self.stats['icmp_packets']}")
        print(f"Unique IPs:        {len(self.stats['unique_ips'])}")
        print(f"Packets/sec:       {pps:.2f}")
        
        # Show recent alerts
        alerts = self.db.get_recent_alerts(5)
        if alerts:
            print("\nRECENT ALERTS:")
            print("-" * 40)
            for alert in alerts:
                print(f"[{alert['timestamp']}] {alert['alert_type']}: {alert['description']}")
        
        print("="*60)
    
    def start(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            print("ERROR: Scapy is not available. Please install it first.")
            return
        
        self.running = True
        self.start_time = datetime.now()
        
        print(f"Starting packet sniffer...")
        print(f"Interface: {self.interface or 'auto-detect'}")
        print(f"Filter: {self.filter_str or 'none'}")
        print("Press Ctrl+C to stop\n")
        
        try:
            # Start statistics display thread
            stats_thread = threading.Thread(target=self.periodic_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self.process_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
            
        except PermissionError:
            print("ERROR: Permission denied. Try running with sudo.")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            print(f"ERROR: {e}")
    
    def periodic_stats(self):
        """Display statistics periodically"""
        while self.running:
            time.sleep(30)  # Show stats every 30 seconds
            if self.running:
                self.print_statistics()
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        self.print_statistics()

def simulate_packets():
    """Simulate packet data for testing when scapy is not available"""
    print("SIMULATION MODE: Generating fake packet data for testing...")
    
    db = PacketDatabase()
    detector = AnomalyDetector()
    
    import random
    ips = ['192.168.1.10', '10.0.0.15', '172.16.0.5', '8.8.8.8', '1.1.1.1']
    ports = [80, 443, 22, 25, 53, 8080, 3389, 1433, 3306]
    protocols = ['TCP', 'UDP', 'ICMP']
    
    packet_count = 0
    
    try:
        while True:
            # Generate random packet
            src_ip = random.choice(ips)
            dst_ip = random.choice(ips)
            protocol = random.choice(protocols)
            
            packet_data = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'packet_size': random.randint(64, 1500),
                'raw_data': f'Simulated {protocol} packet'
            }
            
            if protocol in ['TCP', 'UDP']:
                src_port = random.randint(1024, 65535)
                dst_port = random.choice(ports)
                packet_data.update({
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'flags': 'S' if protocol == 'TCP' else None
                })
                
                # Simulate port scan
                if random.random() < 0.1:  # 10% chance
                    alert = detector.detect_port_scan(src_ip, dst_port)
                    if alert:
                        db.insert_alert(alert)
            
            # Simulate flood
            if random.random() < 0.05:  # 5% chance
                alert = detector.detect_flood(src_ip)
                if alert:
                    db.insert_alert(alert)
            
            db.insert_packet(packet_data)
            packet_count += 1
            
            if packet_count % 10 == 0:
                print(f"[{packet_data['timestamp'].strftime('%H:%M:%S')}] "
                      f"{protocol} {src_ip} -> {dst_ip} "
                      f"({packet_data['packet_size']} bytes)")
            
            if packet_count % 50 == 0:
                print(f"\nGenerated {packet_count} packets...")
                alerts = db.get_recent_alerts(3)
                if alerts:
                    print("Recent alerts:")
                    for alert in alerts:
                        print(f"  - {alert['alert_type']}: {alert['description']}")
            
            time.sleep(0.1)  # Simulate packet rate
            
    except KeyboardInterrupt:
        print(f"\nSimulation stopped. Generated {packet_count} packets.")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='Network Packet Sniffer with Alert System')
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-f', '--filter', help='BPF filter string')
    parser.add_argument('--simulate', action='store_true', help='Run in simulation mode')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    parser.add_argument('--alerts', action='store_true', help='Show recent alerts')
    
    args = parser.parse_args()
    
    if args.stats:
        db = PacketDatabase()
        packets = db.get_recent_packets(10)
        print("Recent packets:")
        for packet in packets:
            print(f"  {packet['timestamp']} - {packet['protocol']} "
                  f"{packet['src_ip']} -> {packet['dst_ip']}")
        return
    
    if args.alerts:
        db = PacketDatabase()
        alerts = db.get_recent_alerts(10)
        print("Recent alerts:")
        for alert in alerts:
            print(f"  [{alert['timestamp']}] {alert['alert_type']}: {alert['description']}")
        return
    
    if args.simulate:
        simulate_packets()
        return
    
    # Start packet sniffer
    sniffer = PacketSniffer(interface=args.interface, filter_str=args.filter)
    sniffer.start()

if __name__ == "__main__":
    main()