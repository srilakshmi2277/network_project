#!/usr/bin/env python3
"""
Enhanced CLI interface for Network Packet Sniffer
Provides detailed analysis and alert management
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import Rectangle
import argparse
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class PacketAnalyzer:
    """Advanced packet analysis and visualization"""
    
    def __init__(self, db_path: str = "packets.db"):
        self.db_path = db_path
        
    def get_traffic_summary(self, hours: int = 1) -> Dict:
        """Get traffic summary for the last N hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get basic statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_packets,
                COUNT(DISTINCT src_ip) as unique_src_ips,
                COUNT(DISTINCT dst_ip) as unique_dst_ips,
                AVG(packet_size) as avg_packet_size,
                MAX(packet_size) as max_packet_size,
                MIN(packet_size) as min_packet_size
            FROM packets 
            WHERE timestamp > ?
        ''', (cutoff_time,))
        
        stats = cursor.fetchone()
        
        # Get protocol distribution
        cursor.execute('''
            SELECT protocol, COUNT(*) as count
            FROM packets 
            WHERE timestamp > ?
            GROUP BY protocol
            ORDER BY count DESC
        ''', (cutoff_time,))
        
        protocols = dict(cursor.fetchall())
        
        # Get top talkers (by packet count)
        cursor.execute('''
            SELECT src_ip, COUNT(*) as packet_count
            FROM packets 
            WHERE timestamp > ?
            GROUP BY src_ip
            ORDER BY packet_count DESC
            LIMIT 10
        ''', (cutoff_time,))
        
        top_talkers = cursor.fetchall()
        
        # Get top destinations
        cursor.execute('''
            SELECT dst_ip, COUNT(*) as packet_count
            FROM packets 
            WHERE timestamp > ?
            GROUP BY dst_ip
            ORDER BY packet_count DESC
            LIMIT 10
        ''', (cutoff_time,))
        
        top_destinations = cursor.fetchall()
        
        conn.close()
        
        return {
            'time_period': f"Last {hours} hour(s)",
            'total_packets': stats[0] if stats[0] else 0,
            'unique_src_ips': stats[1] if stats[1] else 0,
            'unique_dst_ips': stats[2] if stats[2] else 0,
            'avg_packet_size': round(stats[3], 2) if stats[3] else 0,
            'max_packet_size': stats[4] if stats[4] else 0,
            'min_packet_size': stats[5] if stats[5] else 0,
            'protocols': protocols,
            'top_talkers': top_talkers,
            'top_destinations': top_destinations
        }
    
    def get_alert_summary(self, hours: int = 24) -> Dict:
        """Get security alert summary"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get alert counts by type
        cursor.execute('''
            SELECT alert_type, severity, COUNT(*) as count
            FROM alerts 
            WHERE timestamp > ?
            GROUP BY alert_type, severity
            ORDER BY count DESC
        ''', (cutoff_time,))
        
        alert_stats = cursor.fetchall()
        
        # Get recent critical alerts
        cursor.execute('''
            SELECT timestamp, alert_type, description, src_ip
            FROM alerts 
            WHERE timestamp > ? AND severity = 'CRITICAL'
            ORDER BY timestamp DESC
            LIMIT 10
        ''', (cutoff_time,))
        
        critical_alerts = cursor.fetchall()
        
        # Get top attacking IPs
        cursor.execute('''
            SELECT src_ip, COUNT(*) as alert_count
            FROM alerts 
            WHERE timestamp > ? AND src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY alert_count DESC
            LIMIT 10
        ''', (cutoff_time,))
        
        top_attackers = cursor.fetchall()
        
        conn.close()
        
        return {
            'time_period': f"Last {hours} hour(s)",
            'alert_stats': alert_stats,
            'critical_alerts': critical_alerts,
            'top_attackers': top_attackers
        }
    
    def generate_traffic_plot(self, hours: int = 1, save_path: str = "traffic_plot.png"):
        """Generate traffic visualization plot"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get traffic over time (5-minute intervals)
        cursor.execute('''
            SELECT 
                datetime((strftime('%s', timestamp) / 300) * 300, 'unixepoch') as time_slot,
                COUNT(*) as packet_count,
                protocol
            FROM packets 
            WHERE timestamp > ?
            GROUP BY time_slot, protocol
            ORDER BY time_slot
        ''', (cutoff_time,))
        
        data = cursor.fetchall()
        conn.close()
        
        if not data:
            print("No data available for plotting")
            return
        
        # Organize data by protocol
        time_slots = {}
        protocols = set()
        
        for time_slot, count, protocol in data:
            if time_slot not in time_slots:
                time_slots[time_slot] = {}
            time_slots[time_slot][protocol] = count
            protocols.add(protocol)
        
        # Create the plot
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # Plot 1: Traffic over time by protocol
        times = sorted(time_slots.keys())
        times_dt = [datetime.fromisoformat(t.replace('T', ' ')) for t in times]
        
        bottom = [0] * len(times)
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']
        
        for i, protocol in enumerate(sorted(protocols)):
            counts = [time_slots[t].get(protocol, 0) for t in times]
            ax1.bar(times_dt, counts, bottom=bottom, label=protocol, 
                   color=colors[i % len(colors)], alpha=0.8)
            bottom = [b + c for b, c in zip(bottom, counts)]
        
        ax1.set_title(f'Network Traffic Over Time (Last {hours} hours)', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Packets per 5-minute interval')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Format x-axis
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax1.xaxis.set_major_locator(mdates.MinuteLocator(interval=30))
        plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45)
        
        # Plot 2: Protocol distribution (pie chart)
        protocol_totals = {}
        for time_slot, counts in time_slots.items():
            for protocol, count in counts.items():
                protocol_totals[protocol] = protocol_totals.get(protocol, 0) + count
        
        if protocol_totals:
            ax2.pie(protocol_totals.values(), labels=protocol_totals.keys(), 
                   autopct='%1.1f%%', startangle=90, colors=colors)
            ax2.set_title('Protocol Distribution', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Traffic plot saved to: {save_path}")
        return save_path

class EmailAlerter:
    """Send email alerts for security events"""
    
    def __init__(self, smtp_server: str = None, smtp_port: int = 587, 
                 username: str = None, password: str = None, 
                 sender_email: str = None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.sender_email = sender_email or username
        
    def send_alert(self, recipient: str, alert_data: Dict):
        """Send email alert"""
        if not all([self.smtp_server, self.username, self.password]):
            print("Email configuration incomplete. Alert not sent.")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient
            msg['Subject'] = f"Security Alert: {alert_data['alert_type']}"
            
            # Create email body
            body = f"""
SECURITY ALERT NOTIFICATION

Alert Type: {alert_data['alert_type']}
Severity: {alert_data['severity']}
Timestamp: {alert_data['timestamp']}
Description: {alert_data['description']}

Source IP: {alert_data.get('src_ip', 'N/A')}

Details:
{json.dumps(alert_data.get('details', {}), indent=2)}

---
This is an automated alert from your Network Packet Sniffer.
Please investigate this security event promptly.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
            print(f"Alert email sent to {recipient}")
            return True
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
            return False

def print_traffic_summary(summary: Dict):
    """Print formatted traffic summary"""
    print("\n" + "="*70)
    print(f"NETWORK TRAFFIC SUMMARY - {summary['time_period']}")
    print("="*70)
    
    print(f"Total Packets:        {summary['total_packets']:,}")
    print(f"Unique Source IPs:    {summary['unique_src_ips']}")
    print(f"Unique Dest IPs:      {summary['unique_dst_ips']}")
    print(f"Avg Packet Size:      {summary['avg_packet_size']} bytes")
    print(f"Max Packet Size:      {summary['max_packet_size']} bytes")
    print(f"Min Packet Size:      {summary['min_packet_size']} bytes")
    
    if summary['protocols']:
        print(f"\nProtocol Distribution:")
        for protocol, count in summary['protocols'].items():
            percentage = (count / summary['total_packets']) * 100 if summary['total_packets'] > 0 else 0
            print(f"  {protocol:6}: {count:8,} packets ({percentage:5.1f}%)")
    
    if summary['top_talkers']:
        print(f"\nTop Talkers (by packet count):")
        for i, (ip, count) in enumerate(summary['top_talkers'], 1):
            print(f"  {i:2}. {ip:15} - {count:,} packets")
    
    if summary['top_destinations']:
        print(f"\nTop Destinations:")
        for i, (ip, count) in enumerate(summary['top_destinations'], 1):
            print(f"  {i:2}. {ip:15} - {count:,} packets")
    
    print("="*70)

def print_alert_summary(summary: Dict):
    """Print formatted alert summary"""
    print("\n" + "="*70)
    print(f"SECURITY ALERT SUMMARY - {summary['time_period']}")
    print("="*70)
    
    if summary['alert_stats']:
        print("Alert Statistics:")
        total_alerts = sum(count for _, _, count in summary['alert_stats'])
        print(f"Total Alerts: {total_alerts}")
        
        for alert_type, severity, count in summary['alert_stats']:
            print(f"  {alert_type:15} ({severity:8}): {count:3} alerts")
    else:
        print("No alerts in the specified time period.")
    
    if summary['critical_alerts']:
        print(f"\nRecent Critical Alerts:")
        for timestamp, alert_type, description, src_ip in summary['critical_alerts']:
            print(f"  [{timestamp}] {alert_type}")
            print(f"    {description}")
            if src_ip:
                print(f"    Source: {src_ip}")
            print()
    
    if summary['top_attackers']:
        print(f"Top Attacking IPs:")
        for i, (ip, count) in enumerate(summary['top_attackers'], 1):
            print(f"  {i:2}. {ip:15} - {count} alerts")
    
    print("="*70)

def main():
    """Main CLI interface for packet analysis"""
    parser = argparse.ArgumentParser(description='Network Packet Sniffer Analysis Tool')
    parser.add_argument('--traffic', type=int, default=1, 
                       help='Show traffic summary for last N hours (default: 1)')
    parser.add_argument('--alerts', type=int, default=24,
                       help='Show alert summary for last N hours (default: 24)')
    parser.add_argument('--plot', type=int, 
                       help='Generate traffic plot for last N hours')
    parser.add_argument('--db', default='packets.db',
                       help='Database file path (default: packets.db)')
    parser.add_argument('--live', action='store_true',
                       help='Start live monitoring dashboard')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.db):
        print(f"Database file not found: {args.db}")
        print("Run the packet sniffer first to generate data.")
        return
    
    analyzer = PacketAnalyzer(args.db)
    
    # Show traffic summary
    if args.traffic:
        traffic_summary = analyzer.get_traffic_summary(args.traffic)
        print_traffic_summary(traffic_summary)
    
    # Show alert summary
    if args.alerts:
        alert_summary = analyzer.get_alert_summary(args.alerts)
        print_alert_summary(alert_summary)
    
    # Generate plot
    if args.plot:
        plot_path = analyzer.generate_traffic_plot(args.plot)
        print(f"\nTraffic visualization saved to: {plot_path}")
    
    # Live monitoring (simplified version)
    if args.live:
        print("\nLive Monitoring Mode")
        print("Press Ctrl+C to exit")
        
        try:
            import time
            while True:
                os.system('clear')  # Clear screen
                traffic_summary = analyzer.get_traffic_summary(1)
                print_traffic_summary(traffic_summary)
                
                alert_summary = analyzer.get_alert_summary(1)
                if alert_summary['alert_stats']:
                    print_alert_summary(alert_summary)
                
                print(f"\nLast updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("Refreshing in 30 seconds...")
                time.sleep(30)
                
        except KeyboardInterrupt:
            print("\nLive monitoring stopped.")

if __name__ == "__main__":
    main()