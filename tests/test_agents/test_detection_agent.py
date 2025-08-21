"""Tests for DetectionAgent"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.agents.detection_agent import DetectionAgent
from src.data.network_monitor import NetworkPacket
from src.utils.config import Config


class TestDetectionAgent:
    """Test cases for DetectionAgent class"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        config = Config()
        config.set('detection.anomaly_threshold', 0.7)
        config.set('network.monitoring_enabled', False)  # Disable for testing
        config.set('network.packet_buffer_size', 100)
        return config
    
    @pytest.fixture
    def detection_agent(self, config):
        """Create DetectionAgent instance for testing"""
        return DetectionAgent("test_detection_agent", config.config_data)
    
    def test_initialization(self, detection_agent, config):
        """Test DetectionAgent initialization"""
        assert detection_agent.agent_id == "test_detection_agent"
        assert detection_agent.anomaly_threshold == 0.7
        assert not detection_agent.running
        assert len(detection_agent.active_alerts) == 0
        assert detection_agent.start_time > 0
    
    @pytest.mark.asyncio
    async def test_start_stop(self, detection_agent):
        """Test starting and stopping DetectionAgent"""
        # Mock network monitor to avoid actual network monitoring
        with patch.object(detection_agent.network_monitor, 'start'), \
             patch.object(detection_agent.network_monitor, 'stop'):
            
            # Start agent
            start_task = asyncio.create_task(detection_agent.start())
            await asyncio.sleep(0.1)  # Let it initialize
            
            assert detection_agent.running
            assert len(detection_agent.tasks) > 0
            
            # Stop agent
            await detection_agent.stop()
            await start_task
            
            assert not detection_agent.running
    
    def test_port_scan_detection(self, detection_agent):
        """Test port scan detection"""
        # Simulate multiple packets from same IP to different ports
        base_packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=64,
            payload_size=0
        )
        
        # Send packets to many different ports
        for port in range(80, 95):  # 15 different ports
            packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=12345,
                dst_port=port,
                protocol="TCP",
                size=64,
                payload_size=0
            )
            detection_agent._analyze_packet(packet)
        
        # Should detect port scan
        port_scan_alerts = [alert for alert in detection_agent.active_alerts 
                           if alert['type'] == 'port_scan']
        assert len(port_scan_alerts) > 0
        assert port_scan_alerts[0]['source_ip'] == "192.168.1.100"
    
    def test_connection_flood_detection(self, detection_agent):
        """Test connection flood detection"""
        # Simulate many connections from same IP
        for i in range(60):  # Exceed max_connections_per_ip (50)
            packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip="192.168.1.200",
                dst_ip="192.168.1.1",
                src_port=12000 + i,
                dst_port=80,
                protocol="TCP",
                size=64,
                payload_size=0
            )
            detection_agent._analyze_packet(packet)
        
        # Should detect connection flood
        flood_alerts = [alert for alert in detection_agent.active_alerts 
                       if alert['type'] == 'connection_flood']
        assert len(flood_alerts) > 0
        assert flood_alerts[0]['source_ip'] == "192.168.1.200"
    
    def test_suspicious_port_detection(self, detection_agent):
        """Test suspicious port detection"""
        # Create packet accessing suspicious port
        packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.300",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=22,  # SSH port (suspicious)
            protocol="TCP",
            size=64,
            payload_size=0
        )
        
        detection_agent._analyze_packet(packet)
        
        # Should detect suspicious port access
        suspicious_alerts = [alert for alert in detection_agent.active_alerts 
                           if alert['type'] == 'suspicious_port']
        assert len(suspicious_alerts) > 0
        assert suspicious_alerts[0]['details']['suspicious_port'] == 22
    
    def test_ddos_detection(self, detection_agent):
        """Test DDoS detection"""
        # Simulate many packets to same destination
        for i in range(110):  # Exceed DDoS threshold (100)
            packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip=f"192.168.1.{100 + (i % 10)}",  # Different source IPs
                dst_ip="192.168.1.1",  # Same destination
                src_port=12000 + i,
                dst_port=80,
                protocol="TCP",
                size=64,
                payload_size=0
            )
            detection_agent._analyze_packet(packet)
        
        # Should detect DDoS
        ddos_alerts = [alert for alert in detection_agent.active_alerts 
                      if alert['type'] == 'ddos']
        assert len(ddos_alerts) > 0
        assert ddos_alerts[0]['details']['target_ip'] == "192.168.1.1"
    
    @pytest.mark.asyncio
    async def test_get_report(self, detection_agent):
        """Test getting agent report"""
        # Mock the agent as running
        detection_agent.running = True
        
        # Add some test data
        detection_agent.connection_counts["192.168.1.100"] = 5
        
        report = await detection_agent.get_report()
        
        assert report is not None
        assert report['status'] == 'active'
        assert report['agent_type'] == 'detection'
        assert 'total_alerts' in report
        assert 'monitored_ips' in report
        assert 'network_stats' in report
        assert report['monitored_ips'] == 1
    
    @pytest.mark.asyncio
    async def test_get_report_not_running(self, detection_agent):
        """Test getting report when agent not running"""
        detection_agent.running = False
        
        report = await detection_agent.get_report()
        assert report is None
    
    def test_get_alerts(self, detection_agent):
        """Test getting alerts"""
        # Add test alerts
        detection_agent._create_alert(
            "test", "high", "192.168.1.1", "Test alert", {}
        )
        detection_agent._create_alert(
            "test", "low", "192.168.1.2", "Another test alert", {}
        )
        
        # Get all alerts
        all_alerts = detection_agent.get_alerts()
        assert len(all_alerts) == 2
        
        # Get only high severity alerts
        high_alerts = detection_agent.get_alerts(severity="high")
        assert len(high_alerts) == 1
        assert high_alerts[0]['severity'] == "high"
    
    def test_get_suspicious_ips(self, detection_agent):
        """Test getting suspicious IPs"""
        # Initially no suspicious IPs
        suspicious_ips = detection_agent.get_suspicious_ips()
        assert len(suspicious_ips) == 0
        
        # Create alert which marks IP as suspicious
        detection_agent._create_alert(
            "test", "high", "192.168.1.100", "Test alert", {}
        )
        
        # Should now have suspicious IP
        suspicious_ips = detection_agent.get_suspicious_ips()
        assert "192.168.1.100" in suspicious_ips
    
    @pytest.mark.parametrize("port,should_alert", [
        (80, False),   # Normal HTTP port
        (443, False),  # Normal HTTPS port
        (22, True),    # SSH (suspicious)
        (3389, True),  # RDP (suspicious)
        (1433, True),  # SQL Server (suspicious)
    ])
    def test_suspicious_ports(self, detection_agent, port, should_alert):
        """Test detection of various suspicious ports"""
        packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=port,
            protocol="TCP",
            size=64,
            payload_size=0
        )
        
        initial_alert_count = len(detection_agent.active_alerts)
        detection_agent._analyze_packet(packet)
        
        suspicious_alerts = [alert for alert in detection_agent.active_alerts 
                           if alert['type'] == 'suspicious_port']
        
        if should_alert:
            assert len(suspicious_alerts) > 0
        else:
            # Should not have added suspicious port alert
            assert len(detection_agent.active_alerts) == initial_alert_count
