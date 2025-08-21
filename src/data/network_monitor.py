"""Network monitoring and packet capture module"""

import asyncio
import logging
import psutil
import threading
import time
from typing import Dict, List, Any, Optional, Callable, Union
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.utils.logger import get_logger
from src.utils.metrics import metrics


@dataclass
class NetworkPacket:
    """Represents a network packet with relevant IDS information"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    payload_size: int
    flags: str = ""
    raw_data: bytes = b""


@dataclass
class ConnectionInfo:
    """Information about network connections"""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    pid: int
    process_name: str


@dataclass
class ConnectionStats:
    """Statistics for a network connection"""
    count: int = 0
    bytes: int = 0
    last_seen: Optional[datetime] = None


class NetworkMonitor:
    """Real-time network monitoring for intrusion detection"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize network monitor
        
        Args:
            config: Network monitoring configuration
        """
        self.config = config
        self.logger = get_logger('network_monitor')
        self.running = False
        
        # Configuration
        self.monitoring_enabled = config.get('monitoring_enabled', True)
        self.capture_interface = config.get('interface', 'auto')
        self.packet_buffer_size = config.get('packet_buffer_size', 1000)
        self.capture_filter = config.get('capture_filter', '')
        
        # Data storage
        self.packet_buffer = deque(maxlen=self.packet_buffer_size)
        self.connection_stats: Dict[str, ConnectionStats] = defaultdict(ConnectionStats)
        self.suspicious_ips = set()
        
        # Callbacks for packet processing
        self.packet_callbacks: List[Callable[[NetworkPacket], None]] = []
        
        # Threading
        self.monitor_thread = None
        self.stats_thread = None
        
        self.logger.info(f"NetworkMonitor initialized with interface={self.capture_interface}")
    
    def add_packet_callback(self, callback: Callable[[NetworkPacket], None]):
        """Add callback for packet processing
        
        Args:
            callback: Function to call for each packet
        """
        self.packet_callbacks.append(callback)
    
    async def start(self):
        """Start network monitoring"""
        if not self.monitoring_enabled:
            self.logger.info("Network monitoring disabled in configuration")
            return
        
        self.logger.info("Starting network monitoring")
        self.running = True
        
        try:
            # Start monitoring threads
            self.monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
            self.stats_thread = threading.Thread(target=self._collect_network_stats, daemon=True)
            
            self.monitor_thread.start()
            self.stats_thread.start()
            
            self.logger.info("Network monitoring started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting network monitor: {e}")
            self.running = False
            raise
    
    async def stop(self):
        """Stop network monitoring"""
        self.logger.info("Stopping network monitoring")
        self.running = False
        
        # Wait for threads to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=5)
        
        self.logger.info("Network monitoring stopped")
    
    def _monitor_connections(self):
        """Monitor active network connections"""
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                active_connections = []
                
                for conn in connections:
                    # Skip connections without remote address
                    if not hasattr(conn, 'raddr') or not conn.raddr:
                        continue
                    
                    # Skip connections without local address
                    if not hasattr(conn, 'laddr') or not conn.laddr:
                        continue
                        
                    if conn.status == 'ESTABLISHED':
                        try:
                            # Get process information
                            process_name = "unknown"
                            if conn.pid:
                                try:
                                    process = psutil.Process(conn.pid)
                                    process_name = process.name()
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            
                            # Handle different address formats
                            local_ip = conn.laddr[0] if isinstance(conn.laddr, tuple) and len(conn.laddr) >= 1 else "unknown"
                            local_port = conn.laddr[1] if isinstance(conn.laddr, tuple) and len(conn.laddr) >= 2 else 0
                            remote_ip = conn.raddr[0] if isinstance(conn.raddr, tuple) and len(conn.raddr) >= 1 else "unknown"
                            remote_port = conn.raddr[1] if isinstance(conn.raddr, tuple) and len(conn.raddr) >= 2 else 0
                            
                            conn_info = ConnectionInfo(
                                local_ip=local_ip,
                                local_port=local_port,
                                remote_ip=remote_ip,
                                remote_port=remote_port,
                                status=conn.status,
                                pid=conn.pid or 0,
                                process_name=process_name
                            )
                            
                            active_connections.append(conn_info)
                            
                            # Create synthetic packet for analysis
                            packet = self._create_synthetic_packet(conn_info)
                            self._process_packet(packet)
                            
                        except Exception as e:
                            self.logger.debug(f"Error processing connection: {e}")
                
                metrics.record('active_connections', len(active_connections))
                time.sleep(2)  # Monitor every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Error in connection monitoring: {e}")
                time.sleep(5)
    
    def _collect_network_stats(self):
        """Collect network interface statistics"""
        last_stats = psutil.net_io_counters()
        
        while self.running:
            try:
                current_stats = psutil.net_io_counters()
                
                # Calculate rates
                bytes_sent_rate = current_stats.bytes_sent - last_stats.bytes_sent
                bytes_recv_rate = current_stats.bytes_recv - last_stats.bytes_recv
                packets_sent_rate = current_stats.packets_sent - last_stats.packets_sent
                packets_recv_rate = current_stats.packets_recv - last_stats.packets_recv
                
                # Record metrics
                metrics.record('network_bytes_sent_rate', bytes_sent_rate)
                metrics.record('network_bytes_recv_rate', bytes_recv_rate)
                metrics.record('network_packets_sent_rate', packets_sent_rate)
                metrics.record('network_packets_recv_rate', packets_recv_rate)
                metrics.record('network_errors', current_stats.errin + current_stats.errout)
                metrics.record('network_drops', current_stats.dropin + current_stats.dropout)
                
                last_stats = current_stats
                time.sleep(5)  # Collect stats every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error collecting network stats: {e}")
                time.sleep(10)
    
    def _create_synthetic_packet(self, conn_info: ConnectionInfo) -> NetworkPacket:
        """Create synthetic packet from connection info
        
        Args:
            conn_info: Connection information
            
        Returns:
            Synthetic network packet
        """
        return NetworkPacket(
            timestamp=datetime.now(),
            src_ip=conn_info.local_ip,
            dst_ip=conn_info.remote_ip,
            src_port=conn_info.local_port,
            dst_port=conn_info.remote_port,
            protocol="TCP",
            size=64,  # Synthetic size
            payload_size=0,
            flags="ESTABLISHED"
        )
    
    def _process_packet(self, packet: NetworkPacket):
        """Process a network packet
        
        Args:
            packet: Network packet to process
        """
        try:
            # Add to buffer
            self.packet_buffer.append(packet)
            
            # Update connection statistics
            conn_key = f"{packet.src_ip}:{packet.src_port}->{packet.dst_ip}:{packet.dst_port}"
            stats = self.connection_stats[conn_key]
            stats.count += 1
            stats.bytes += packet.size
            stats.last_seen = packet.timestamp
            
            # Call registered callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    self.logger.error(f"Error in packet callback: {e}")
            
            metrics.increment('packets_processed')
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def get_recent_packets(self, count: int = 100) -> List[NetworkPacket]:
        """Get recent packets
        
        Args:
            count: Number of recent packets to return
            
        Returns:
            List of recent packets
        """
        return list(self.packet_buffer)[-count:]
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics
        
        Returns:
            Dictionary of connection statistics
        """
        active_connections = len([
            conn for conn, stats in self.connection_stats.items()
            if stats.last_seen and 
            datetime.now() - stats.last_seen < timedelta(minutes=5)
        ])
        
        return {
            'total_connections': len(self.connection_stats),
            'active_connections': active_connections,
            'packets_processed': metrics.get_counter('packets_processed'),
            'suspicious_ips': len(self.suspicious_ips),
            'buffer_usage': len(self.packet_buffer)
        }
    
    def is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is marked as suspicious
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is suspicious
        """
        return ip in self.suspicious_ips
    
    def mark_suspicious_ip(self, ip: str, reason: str = ""):
        """Mark IP as suspicious
        
        Args:
            ip: IP address to mark
            reason: Reason for marking as suspicious
        """
        self.suspicious_ips.add(ip)
        self.logger.warning(f"Marked IP {ip} as suspicious: {reason}")
        metrics.increment('suspicious_ips_detected')
    
    def get_top_connections(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top connections by activity
        
        Args:
            limit: Maximum number of connections to return
            
        Returns:
            List of top connections
        """
        sorted_connections = sorted(
            self.connection_stats.items(),
            key=lambda x: x[1].count,
            reverse=True
        )
        
        return [
            {
                'connection': conn,
                'count': stats.count,
                'bytes': stats.bytes,
                'last_seen': stats.last_seen.isoformat() if stats.last_seen else None
            }
            for conn, stats in sorted_connections[:limit]
        ]
