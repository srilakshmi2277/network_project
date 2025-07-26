#!/usr/bin/env python3
"""
Demo script for Network Packet Sniffer
Generates realistic packet data with security events for demonstration
"""

import random
import time
from datetime import datetime, timedelta
import sys
import os

# Add current directory to path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from packet_sniffer import PacketDatabase, AnomalyDetector

def generate_port_scan_attack():
    """Simulate a port scanning attack"""
    print("🚨 Simulating PORT SCAN attack...")
    
    db = PacketDatabase()
    detector = AnomalyDetector()
    
    # Attacker IP
    attacker_ip = "192.168.1.100"
    target_ip = "10.0.0.50"
    
    # Scan common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389]
    
    for port in common_ports:
        packet_data = {
            'timestamp': datetime.now(),
            'src_ip': attacker_ip,
            'dst_ip': target_ip,
            'src_port': random.randint(40000, 60000),
            'dst_port': port,
            'protocol': 'TCP',
            'packet_size': random.randint(60, 120),
            'flags': 'S',  # SYN flag for TCP connect scan
            'raw_data': f'TCP SYN scan to port {port}'
        }
        
        db.insert_packet(packet_data)
        
        # Check for port scan detection
        alert = detector.detect_port_scan(attacker_ip, port)
        if alert:
            db.insert_alert(alert)
            print(f"🔴 ALERT: {alert['description']}")
        
        time.sleep(0.1)  # Small delay between packets

def generate_flood_attack():
    """Simulate a flooding/DDoS attack"""
    print("🚨 Simulating FLOOD attack...")
    
    db = PacketDatabase()
    detector = AnomalyDetector()
    
    # Attacker IP
    attacker_ip = "203.0.113.10"
    target_ip = "10.0.0.100"
    
    # Generate flood of packets
    for i in range(150):  # More than flood threshold (100)
        packet_data = {
            'timestamp': datetime.now(),
            'src_ip': attacker_ip,
            'dst_ip': target_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': random.randint(1200, 1500),
            'flags': 'A',  # ACK flood
            'raw_data': f'Flood packet #{i+1}'
        }
        
        db.insert_packet(packet_data)
        
        # Check for flood detection
        alert = detector.detect_flood(attacker_ip)
        if alert:
            db.insert_alert(alert)
            print(f"🔴 ALERT: {alert['description']}")
            # Only print first alert to avoid spam
            break
        
        if i % 25 == 0:
            print(f"   Sent {i+1} packets...")
        
        time.sleep(0.05)  # Very fast packets for flood

def generate_normal_traffic():
    """Generate normal network traffic"""
    print("📡 Generating normal network traffic...")
    
    db = PacketDatabase()
    
    # Common legitimate traffic patterns
    legitimate_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']  # DNS servers
    internal_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30']
    web_ports = [80, 443, 8080]
    service_ports = [53, 25, 110, 143, 993, 995]
    
    for i in range(200):  # Generate normal traffic
        # Random traffic pattern
        if random.random() < 0.6:  # 60% web traffic
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(legitimate_servers)
            dst_port = random.choice(web_ports)
            protocol = 'TCP'
        elif random.random() < 0.3:  # 30% DNS queries
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(legitimate_servers)
            dst_port = 53
            protocol = 'UDP'
        else:  # 10% other services
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(internal_ips)
            dst_port = random.choice(service_ports)
            protocol = random.choice(['TCP', 'UDP'])
        
        packet_data = {
            'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 3600)),  # Spread over last hour
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': random.randint(64, 1500),
            'flags': 'A' if protocol == 'TCP' else None,
            'raw_data': f'Normal {protocol} traffic'
        }
        
        db.insert_packet(packet_data)
        
        if i % 50 == 0 and i > 0:
            print(f"   Generated {i} normal packets...")
        
        time.sleep(0.01)

def demo_scenario():
    """Run a complete demo scenario"""
    print("🎭 Starting Network Packet Sniffer Demo")
    print("=" * 50)
    
    # Clean slate - remove existing database
    if os.path.exists("packets.db"):
        os.remove("packets.db")
        print("🗑️  Cleared existing database")
    
    print("\n1️⃣ Generating normal network traffic...")
    generate_normal_traffic()
    
    print("\n2️⃣ Simulating security attacks...")
    generate_port_scan_attack()
    time.sleep(2)  # Brief pause between attacks
    generate_flood_attack()
    
    print(f"\n✅ Demo completed! Database contains simulated network data.")
    print(f"📊 Run analysis tools:")
    print(f"   python packet_analyzer.py --traffic 1")
    print(f"   python packet_analyzer.py --alerts 1") 
    print(f"   python packet_analyzer.py --plot 1")
    print(f"   python packet_sniffer.py --stats")
    print(f"   python packet_sniffer.py --alerts")

if __name__ == "__main__":
    demo_scenario()