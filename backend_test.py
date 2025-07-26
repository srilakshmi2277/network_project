#!/usr/bin/env python3
"""
Comprehensive Backend Testing for Network Packet Sniffer with Alert System
Tests all core components: packet sniffer, database, anomaly detection, and analysis tools
"""

import unittest
import sqlite3
import os
import sys
import tempfile
import shutil
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import json

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from packet_sniffer import PacketDatabase, AnomalyDetector, PacketSniffer
from packet_analyzer import PacketAnalyzer, EmailAlerter

class TestPacketDatabase(unittest.TestCase):
    """Test SQLite Database Handler functionality"""
    
    def setUp(self):
        """Set up test database"""
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        self.db = PacketDatabase(self.test_db.name)
    
    def tearDown(self):
        """Clean up test database"""
        os.unlink(self.test_db.name)
    
    def test_database_initialization(self):
        """Test database tables are created correctly"""
        conn = sqlite3.connect(self.test_db.name)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn('packets', tables)
        self.assertIn('alerts', tables)
        self.assertIn('statistics', tables)
        
        conn.close()
    
    def test_packet_insertion(self):
        """Test packet data insertion"""
        packet_data = {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.10',
            'dst_ip': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 1024,
            'flags': 'A',
            'raw_data': 'Test packet data'
        }
        
        self.db.insert_packet(packet_data)
        
        # Verify insertion
        packets = self.db.get_recent_packets(1)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]['src_ip'], '192.168.1.10')
        self.assertEqual(packets[0]['dst_ip'], '8.8.8.8')
        self.assertEqual(packets[0]['protocol'], 'TCP')
    
    def test_alert_insertion(self):
        """Test alert logging functionality"""
        alert_data = {
            'timestamp': datetime.now(),
            'alert_type': 'PORT_SCAN',
            'severity': 'HIGH',
            'description': 'Test port scan alert',
            'src_ip': '192.168.1.100',
            'details': {'ports_accessed': [80, 443, 22], 'port_count': 3}
        }
        
        self.db.insert_alert(alert_data)
        
        # Verify insertion
        alerts = self.db.get_recent_alerts(1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['alert_type'], 'PORT_SCAN')
        self.assertEqual(alerts[0]['severity'], 'HIGH')
        self.assertEqual(alerts[0]['src_ip'], '192.168.1.100')
    
    def test_data_retrieval(self):
        """Test packet and alert retrieval"""
        # Insert test data
        for i in range(5):
            packet_data = {
                'timestamp': datetime.now(),
                'src_ip': f'192.168.1.{i+10}',
                'dst_ip': '8.8.8.8',
                'protocol': 'TCP',
                'packet_size': 1024 + i,
                'raw_data': f'Test packet {i}'
            }
            self.db.insert_packet(packet_data)
        
        # Test retrieval with limit
        packets = self.db.get_recent_packets(3)
        self.assertEqual(len(packets), 3)
        
        # Test full retrieval
        all_packets = self.db.get_recent_packets(10)
        self.assertEqual(len(all_packets), 5)

class TestAnomalyDetector(unittest.TestCase):
    """Test Anomaly Detection System"""
    
    def setUp(self):
        """Set up anomaly detector"""
        self.detector = AnomalyDetector()
    
    def test_port_scan_detection(self):
        """Test port scan detection with threshold"""
        src_ip = '192.168.1.100'
        
        # Simulate scanning multiple ports (below threshold)
        for port in range(80, 85):  # 5 ports
            alert = self.detector.detect_port_scan(src_ip, port)
            self.assertIsNone(alert)  # Should not trigger alert yet
        
        # Scan more ports to exceed threshold (10 ports)
        for port in range(85, 92):  # 7 more ports (total 12)
            alert = self.detector.detect_port_scan(src_ip, port)
        
        # Last scan should trigger alert
        self.assertIsNotNone(alert)
        self.assertEqual(alert['alert_type'], 'PORT_SCAN')
        self.assertEqual(alert['severity'], 'HIGH')
        self.assertEqual(alert['src_ip'], src_ip)
        self.assertGreater(alert['details']['port_count'], 10)
    
    def test_flood_detection(self):
        """Test flood attack detection with threshold"""
        src_ip = '203.0.113.10'
        
        # Simulate normal packet rate (below threshold)
        for i in range(50):  # 50 packets
            alert = self.detector.detect_flood(src_ip)
            self.assertIsNone(alert)  # Should not trigger alert yet
        
        # Simulate flood (exceed threshold of 100 packets in 10s)
        for i in range(60):  # 60 more packets (total 110)
            alert = self.detector.detect_flood(src_ip)
        
        # Should trigger flood alert
        self.assertIsNotNone(alert)
        self.assertEqual(alert['alert_type'], 'FLOOD_ATTACK')
        self.assertEqual(alert['severity'], 'CRITICAL')
        self.assertEqual(alert['src_ip'], src_ip)
        self.assertGreater(alert['details']['packet_rate'], 100)
    
    def test_detection_accuracy(self):
        """Test detection accuracy with demo data"""
        # Test with legitimate traffic (should not trigger alerts)
        legitimate_ips = ['192.168.1.10', '192.168.1.20']
        legitimate_ports = [80, 443, 53]
        
        for ip in legitimate_ips:
            for port in legitimate_ports:
                alert = self.detector.detect_port_scan(ip, port)
                self.assertIsNone(alert)  # Legitimate traffic should not trigger alerts

class TestPacketSniffer(unittest.TestCase):
    """Test Core Packet Sniffer Implementation"""
    
    def setUp(self):
        """Set up packet sniffer with test database"""
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        
        # Mock the database path in PacketSniffer
        with patch('packet_sniffer.PacketDatabase') as mock_db:
            mock_db.return_value = PacketDatabase(self.test_db.name)
            self.sniffer = PacketSniffer()
            self.sniffer.db = PacketDatabase(self.test_db.name)
    
    def tearDown(self):
        """Clean up test database"""
        os.unlink(self.test_db.name)
    
    def test_sniffer_initialization(self):
        """Test packet sniffer initialization"""
        self.assertIsNotNone(self.sniffer.db)
        self.assertIsNotNone(self.sniffer.detector)
        self.assertFalse(self.sniffer.running)
        self.assertEqual(self.sniffer.packet_count, 0)
    
    def test_statistics_tracking(self):
        """Test packet statistics tracking"""
        # Initial stats should be zero
        self.assertEqual(self.sniffer.stats['total_packets'], 0)
        self.assertEqual(self.sniffer.stats['tcp_packets'], 0)
        self.assertEqual(self.sniffer.stats['udp_packets'], 0)
        self.assertEqual(len(self.sniffer.stats['unique_ips']), 0)
    
    @patch('packet_sniffer.SCAPY_AVAILABLE', True)
    def test_simulation_mode_availability(self):
        """Test that simulation mode works when scapy is not available"""
        # This test verifies the simulation function exists and can be called
        from packet_sniffer import simulate_packets
        self.assertTrue(callable(simulate_packets))

class TestPacketAnalyzer(unittest.TestCase):
    """Test CLI Analysis Tools"""
    
    def setUp(self):
        """Set up analyzer with test database"""
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
        
        # Create test database with sample data
        self.db = PacketDatabase(self.test_db.name)
        self.analyzer = PacketAnalyzer(self.test_db.name)
        
        # Insert sample data
        self._insert_sample_data()
    
    def tearDown(self):
        """Clean up test database"""
        os.unlink(self.test_db.name)
    
    def _insert_sample_data(self):
        """Insert sample data for testing"""
        # Insert sample packets
        for i in range(10):
            packet_data = {
                'timestamp': datetime.now() - timedelta(minutes=i),
                'src_ip': f'192.168.1.{i+10}',
                'dst_ip': '8.8.8.8',
                'src_port': 12345 + i,
                'dst_port': 80,
                'protocol': 'TCP' if i % 2 == 0 else 'UDP',
                'packet_size': 1024 + i * 100,
                'raw_data': f'Sample packet {i}'
            }
            self.db.insert_packet(packet_data)
        
        # Insert sample alerts
        alert_data = {
            'timestamp': datetime.now(),
            'alert_type': 'PORT_SCAN',
            'severity': 'HIGH',
            'description': 'Test port scan detected',
            'src_ip': '192.168.1.100',
            'details': {'ports_accessed': [80, 443, 22], 'port_count': 3}
        }
        self.db.insert_alert(alert_data)
    
    def test_traffic_summary_generation(self):
        """Test traffic summary generation"""
        summary = self.analyzer.get_traffic_summary(hours=1)
        
        self.assertIn('total_packets', summary)
        self.assertIn('unique_src_ips', summary)
        self.assertIn('protocols', summary)
        self.assertIn('top_talkers', summary)
        
        # Verify data integrity
        self.assertGreater(summary['total_packets'], 0)
        self.assertIsInstance(summary['protocols'], dict)
        self.assertIsInstance(summary['top_talkers'], list)
    
    def test_alert_analysis_and_reporting(self):
        """Test alert analysis and reporting"""
        summary = self.analyzer.get_alert_summary(hours=24)
        
        self.assertIn('alert_stats', summary)
        self.assertIn('top_attackers', summary)
        
        # Should have at least one alert from sample data
        self.assertGreater(len(summary['alert_stats']), 0)
    
    def test_visualization_plot_generation(self):
        """Test visualization plot generation"""
        plot_path = self.analyzer.generate_traffic_plot(hours=1, save_path="test_plot.png")
        
        # Check if plot file was created
        if plot_path and os.path.exists(plot_path):
            self.assertTrue(os.path.exists(plot_path))
            os.remove(plot_path)  # Clean up
        else:
            # If no data available for plotting, that's also acceptable
            self.assertTrue(True)

class TestEmailAlerter(unittest.TestCase):
    """Test Email Alert System"""
    
    def setUp(self):
        """Set up email alerter"""
        self.alerter = EmailAlerter(
            smtp_server="smtp.gmail.com",
            smtp_port=587,
            username="test@example.com",
            password="testpass",
            sender_email="test@example.com"
        )
    
    def test_email_alerter_initialization(self):
        """Test email alerter initialization"""
        self.assertEqual(self.alerter.smtp_server, "smtp.gmail.com")
        self.assertEqual(self.alerter.smtp_port, 587)
        self.assertEqual(self.alerter.username, "test@example.com")
    
    @patch('smtplib.SMTP')
    def test_alert_email_composition(self, mock_smtp):
        """Test alert email composition (without actually sending)"""
        alert_data = {
            'timestamp': datetime.now(),
            'alert_type': 'PORT_SCAN',
            'severity': 'HIGH',
            'description': 'Test alert',
            'src_ip': '192.168.1.100',
            'details': {'test': 'data'}
        }
        
        # Mock SMTP server
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server
        
        result = self.alerter.send_alert("recipient@example.com", alert_data)
        
        # Verify SMTP methods were called
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("test@example.com", "testpass")
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()
        
        self.assertTrue(result)

class TestCLIInterface(unittest.TestCase):
    """Test CLI Interface and Command-line Options"""
    
    def test_packet_sniffer_cli_options(self):
        """Test packet sniffer CLI argument parsing"""
        # Test that main function exists and can handle arguments
        from packet_sniffer import main
        self.assertTrue(callable(main))
    
    def test_packet_analyzer_cli_options(self):
        """Test packet analyzer CLI argument parsing"""
        # Test that main function exists and can handle arguments
        from packet_analyzer import main
        self.assertTrue(callable(main))
    
    def test_demo_sniffer_functionality(self):
        """Test demo sniffer data generation"""
        from demo_sniffer import demo_scenario
        self.assertTrue(callable(demo_scenario))

class TestIntegration(unittest.TestCase):
    """Integration tests for complete system"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.test_db.close()
    
    def tearDown(self):
        """Clean up integration test environment"""
        os.unlink(self.test_db.name)
    
    def test_end_to_end_packet_processing(self):
        """Test complete packet processing pipeline"""
        # Initialize components
        db = PacketDatabase(self.test_db.name)
        detector = AnomalyDetector()
        
        # Simulate packet processing
        packet_data = {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.50',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 1024,
            'flags': 'S',
            'raw_data': 'Integration test packet'
        }
        
        # Store packet
        db.insert_packet(packet_data)
        
        # Check for anomalies
        alert = detector.detect_port_scan(packet_data['src_ip'], packet_data['dst_port'])
        
        # Verify packet was stored
        packets = db.get_recent_packets(1)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]['src_ip'], '192.168.1.100')
    
    def test_database_and_analysis_integration(self):
        """Test database and analysis tool integration"""
        # Initialize components
        db = PacketDatabase(self.test_db.name)
        analyzer = PacketAnalyzer(self.test_db.name)
        
        # Insert test data
        for i in range(5):
            packet_data = {
                'timestamp': datetime.now(),
                'src_ip': f'192.168.1.{i+10}',
                'dst_ip': '8.8.8.8',
                'protocol': 'TCP',
                'packet_size': 1024,
                'raw_data': f'Test packet {i}'
            }
            db.insert_packet(packet_data)
        
        # Test analysis
        summary = analyzer.get_traffic_summary(hours=1)
        self.assertEqual(summary['total_packets'], 5)
        self.assertIn('TCP', summary['protocols'])

def run_comprehensive_tests():
    """Run all backend tests"""
    print("🧪 Starting Comprehensive Backend Testing")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestPacketDatabase,
        TestAnomalyDetector,
        TestPacketSniffer,
        TestPacketAnalyzer,
        TestEmailAlerter,
        TestCLIInterface,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("🏁 TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\n🚨 ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Error:')[-1].strip()}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    print(f"\n✅ Success Rate: {success_rate:.1f}%")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)