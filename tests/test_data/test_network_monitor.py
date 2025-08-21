"""Tests for NetworkMonitor"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.data.network_monitor import NetworkMonitor, NetworkPacket, ConnectionInfo
from src.utils.config import Config


class TestNetworkMonitor:
    """Test cases for NetworkMonitor class"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return {
            'monitoring_enabled': False,  # Disable actual monitoring for tests
            'interface': 'test',
            'packet_buffer_size': 100,
            'capture_filter': ''
        }
    
    @pytest.fixture
    def network_monitor(self, config):
        """Create NetworkMonitor instance for testing"""
        return NetworkMonitor(config)
    
    def test_initialization(self, network_monitor, config):
        """Test NetworkMonitor initialization"""
        assert not network_monitor.monitoring_enabled
        assert network_monitor.capture_interface == 'test'
        assert network_monitor.packet_buffer_size == 100
        assert not network_monitor.running
        assert len(network_monitor.packet_buffer) == 0
    
    @pytest.mark.asyncio
    async def test_start_stop_disabled(self, network_monitor):
        """Test starting and stopping with monitoring disabled"""
        await network_monitor.start()
        assert not network_monitor.running  # Should remain False when disabled
        
        await network_monitor.stop()
        assert not network_monitor.running
    
    @pytest.mark.asyncio
    async def test_start_stop_enabled(self):
        """Test starting and stopping with monitoring enabled"""
        config = {
            'monitoring_enabled': True,
            'interface': 'test',
            'packet_buffer_size': 100
        }
        
        monitor = NetworkMonitor(config)
        
        # Mock the threading to avoid actual network monitoring
        with patch('threading.Thread') as mock_thread:
            mock_thread_instance = MagicMock()
            mock_thread.return_value = mock_thread_instance
            
            await monitor.start()
            assert monitor.running
            assert mock_thread.call_count == 2  # Two threads should be created
            
            await monitor.stop()
            assert not monitor.running
    
    def test_packet_callback(self, network_monitor):
        """Test packet callback functionality"""
        callback_called = False
        received_packet = None
        
        def test_callback(packet):
            nonlocal callback_called, received_packet
            callback_called = True
            received_packet = packet
        
        network_monitor.add_packet_callback(test_callback)
        
        # Create test packet
        test_packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=64,
            payload_size=0
        )
        
        # Process packet
        network_monitor._process_packet(test_packet)
        
        assert callback_called
        assert received_packet == test_packet
    
    def test_process_packet(self, network_monitor):
        """Test packet processing"""
        test_packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=64,
            payload_size=0
        )
        
        # Process packet
        network_monitor._process_packet(test_packet)
        
        # Check packet buffer
        assert len(network_monitor.packet_buffer) == 1
        assert network_monitor.packet_buffer[0] == test_packet
        
        # Check connection stats
        conn_key = "192.168.1.1:12345->192.168.1.2:80"
        assert conn_key in network_monitor.connection_stats
        stats = network_monitor.connection_stats[conn_key]
        assert stats.count == 1
        assert stats.bytes == 64
        assert stats.last_seen == test_packet.timestamp
    
    def test_get_recent_packets(self, network_monitor):
        """Test getting recent packets"""
        # Add test packets
        for i in range(5):
            packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip=f"192.168.1.{i}",
                dst_ip="192.168.1.100",
                src_port=12345 + i,
                dst_port=80,
                protocol="TCP",
                size=64,
                payload_size=0
            )
            network_monitor._process_packet(packet)
        
        # Get recent packets
        recent = network_monitor.get_recent_packets(3)
        assert len(recent) == 3
        
        # Should get the last 3 packets
        assert recent[0].src_ip == "192.168.1.2"
        assert recent[1].src_ip == "192.168.1.3"
        assert recent[2].src_ip == "192.168.1.4"
    
    def test_connection_stats(self, network_monitor):
        """Test connection statistics"""
        # Process multiple packets for same connection
        for i in range(3):
            packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                size=100,
                payload_size=0
            )
            network_monitor._process_packet(packet)
        
        stats = network_monitor.get_connection_stats()
        assert stats['total_connections'] == 1
        assert stats['packets_processed'] >= 3
        assert stats['buffer_usage'] == 3
    
    def test_suspicious_ip_management(self, network_monitor):
        """Test suspicious IP marking and checking"""
        test_ip = "192.168.1.100"
        
        # Initially not suspicious
        assert not network_monitor.is_suspicious_ip(test_ip)
        assert len(network_monitor.suspicious_ips) == 0
        
        # Mark as suspicious
        network_monitor.mark_suspicious_ip(test_ip, "test reason")
        
        # Should now be suspicious
        assert network_monitor.is_suspicious_ip(test_ip)
        assert test_ip in network_monitor.suspicious_ips
    
    def test_top_connections(self, network_monitor):
        """Test getting top connections by activity"""
        # Create connections with different activity levels
        connections = [
            ("192.168.1.1", "192.168.1.100", 12345, 80, 10),  # 10 packets
            ("192.168.1.2", "192.168.1.100", 12346, 80, 5),   # 5 packets
            ("192.168.1.3", "192.168.1.100", 12347, 80, 15),  # 15 packets
        ]
        
        for src_ip, dst_ip, src_port, dst_port, packet_count in connections:
            for i in range(packet_count):
                packet = NetworkPacket(
                    timestamp=datetime.now(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="TCP",
                    size=64,
                    payload_size=0
                )
                network_monitor._process_packet(packet)
        
        # Get top connections
        top_connections = network_monitor.get_top_connections(2)
        assert len(top_connections) == 2
        
        # Should be sorted by activity (highest first)
        assert top_connections[0]['count'] == 15  # 192.168.1.3
        assert top_connections[1]['count'] == 10  # 192.168.1.1
    
    def test_buffer_size_limit(self, network_monitor):
        """Test that packet buffer respects size limit"""
        buffer_size = network_monitor.packet_buffer_size
        
        # Add more packets than buffer size
        for i in range(buffer_size + 10):
            packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip=f"192.168.1.{i % 256}",
                dst_ip="192.168.1.100",
                src_port=12345 + i,
                dst_port=80,
                protocol="TCP",
                size=64,
                payload_size=0
            )
            network_monitor._process_packet(packet)
        
        # Buffer should not exceed max size
        assert len(network_monitor.packet_buffer) == buffer_size
    
    def test_create_synthetic_packet(self, network_monitor):
        """Test creating synthetic packet from connection info"""
        conn_info = ConnectionInfo(
            local_ip="192.168.1.1",
            local_port=12345,
            remote_ip="192.168.1.2",
            remote_port=80,
            status="ESTABLISHED",
            pid=1234,
            process_name="test_process"
        )
        
        packet = network_monitor._create_synthetic_packet(conn_info)
        
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.src_port == 12345
        assert packet.dst_port == 80
        assert packet.protocol == "TCP"
        assert packet.flags == "ESTABLISHED"


class TestNetworkPacket:
    """Test cases for NetworkPacket dataclass"""
    
    def test_packet_creation(self):
        """Test creating a network packet"""
        timestamp = datetime.now()
        packet = NetworkPacket(
            timestamp=timestamp,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=1500,
            payload_size=1400,
            flags="SYN",
            raw_data=b"test data"
        )
        
        assert packet.timestamp == timestamp
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.src_port == 12345
        assert packet.dst_port == 80
        assert packet.protocol == "TCP"
        assert packet.size == 1500
        assert packet.payload_size == 1400
        assert packet.flags == "SYN"
        assert packet.raw_data == b"test data"


class TestConnectionInfo:
    """Test cases for ConnectionInfo dataclass"""
    
    def test_connection_info_creation(self):
        """Test creating connection info"""
        conn_info = ConnectionInfo(
            local_ip="192.168.1.1",
            local_port=12345,
            remote_ip="192.168.1.2",
            remote_port=80,
            status="ESTABLISHED",
            pid=1234,
            process_name="firefox"
        )
        
        assert conn_info.local_ip == "192.168.1.1"
        assert conn_info.local_port == 12345
        assert conn_info.remote_ip == "192.168.1.2"
        assert conn_info.remote_port == 80
        assert conn_info.status == "ESTABLISHED"
        assert conn_info.pid == 1234
        assert conn_info.process_name == "firefox"
