"""Detection agent for real-time network intrusion detection"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from src.agents.base_agent import BaseAgent
from src.data.network_monitor import NetworkMonitor, NetworkPacket
from src.utils.logger import get_logger
from src.utils.metrics import metrics


class DetectionAgent(BaseAgent):
    """Agent responsible for detecting network intrusions"""
    
    def __init__(self, agent_id: str, config: Dict[str, Any]):
        """Initialize detection agent
        
        Args:
            agent_id: Unique identifier for the agent
            config: Agent configuration
        """
        super().__init__(agent_id, config)
        
        self.network_monitor = NetworkMonitor(config.get('network', {}))
        self.detection_config = config.get('detection', {})
        
        # Detection parameters
        self.anomaly_threshold = self.detection_config.get('anomaly_threshold', 0.8)
        self.suspicious_ports = {22, 23, 135, 139, 445, 1433, 3389, 5432}
        self.max_connections_per_ip = 50
        self.max_failed_attempts = 10
        
        # Detection state
        self.suspicious_activities: List[Dict[str, Any]] = []
        self.connection_counts = defaultdict(int)
        self.failed_attempts = defaultdict(int)
        self.port_scan_detection = defaultdict(set)
        self.ddos_detection = defaultdict(list)
        
        # Alerts
        self.active_alerts: List[Dict[str, Any]] = []
        self.start_time = time.time()
        
        self.logger.info(f"DetectionAgent {agent_id} initialized with threshold={self.anomaly_threshold}")
    
    async def _on_start(self):
        """Called when agent starts"""
        # Register packet callback with network monitor
        self.network_monitor.add_packet_callback(self._analyze_packet)
        
        # Start network monitoring
        await self.network_monitor.start()
        
        # Start detection tasks
        self.tasks.append(asyncio.create_task(self._periodic_analysis()))
        self.tasks.append(asyncio.create_task(self._cleanup_old_data()))
        
        self.logger.info(f"DetectionAgent {self.agent_id} started")
    
    async def _on_stop(self):
        """Called when agent stops"""
        await self.network_monitor.stop()
        self.logger.info(f"DetectionAgent {self.agent_id} stopped")
    
    def _analyze_packet(self, packet: NetworkPacket):
        """Analyze individual packet for suspicious activity
        
        Args:
            packet: Network packet to analyze
        """
        try:
            # Port scan detection
            self._detect_port_scan(packet)
            
            # Connection flood detection
            self._detect_connection_flood(packet)
            
            # Suspicious port access
            self._detect_suspicious_ports(packet)
            
            # DDoS detection
            self._detect_ddos(packet)
            
            metrics.increment('packets_analyzed')
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
    
    def _detect_port_scan(self, packet: NetworkPacket):
        """Detect port scanning attempts
        
        Args:
            packet: Network packet to analyze
        """
        src_ip = packet.src_ip
        dst_port = packet.dst_port
        
        # Track unique ports accessed by source IP
        self.port_scan_detection[src_ip].add(dst_port)
        
        # Alert if single IP accesses many different ports
        unique_ports = len(self.port_scan_detection[src_ip])
        if unique_ports > 10:  # Threshold for port scan
            self._create_alert(
                alert_type="port_scan",
                severity="high",
                source_ip=src_ip,
                description=f"Port scan detected: {src_ip} accessed {unique_ports} different ports",
                details={
                    'source_ip': src_ip,
                    'ports_accessed': list(self.port_scan_detection[src_ip]),
                    'unique_ports_count': unique_ports
                }
            )
            metrics.increment('port_scans_detected')
    
    def _detect_connection_flood(self, packet: NetworkPacket):
        """Detect connection flooding attempts
        
        Args:
            packet: Network packet to analyze
        """
        src_ip = packet.src_ip
        self.connection_counts[src_ip] += 1
        
        # Alert if single IP makes too many connections
        if self.connection_counts[src_ip] > self.max_connections_per_ip:
            self._create_alert(
                alert_type="connection_flood",
                severity="medium",
                source_ip=src_ip,
                description=f"Connection flood detected: {src_ip} made {self.connection_counts[src_ip]} connections",
                details={
                    'source_ip': src_ip,
                    'connection_count': self.connection_counts[src_ip],
                    'threshold': self.max_connections_per_ip
                }
            )
            metrics.increment('connection_floods_detected')
    
    def _detect_suspicious_ports(self, packet: NetworkPacket):
        """Detect access to suspicious ports
        
        Args:
            packet: Network packet to analyze
        """
        if packet.dst_port in self.suspicious_ports:
            self._create_alert(
                alert_type="suspicious_port",
                severity="medium",
                source_ip=packet.src_ip,
                description=f"Access to suspicious port {packet.dst_port} from {packet.src_ip}",
                details={
                    'source_ip': packet.src_ip,
                    'destination_ip': packet.dst_ip,
                    'suspicious_port': packet.dst_port,
                    'protocol': packet.protocol
                }
            )
            metrics.increment('suspicious_port_access')
    
    def _detect_ddos(self, packet: NetworkPacket):
        """Detect potential DDoS attacks
        
        Args:
            packet: Network packet to analyze
        """
        dst_ip = packet.dst_ip
        current_time = datetime.now()
        
        # Track packets to destination IP
        self.ddos_detection[dst_ip].append(current_time)
        
        # Keep only recent packets (last minute)
        cutoff_time = current_time - timedelta(minutes=1)
        self.ddos_detection[dst_ip] = [
            t for t in self.ddos_detection[dst_ip] if t > cutoff_time
        ]
        
        # Alert if too many packets to single destination
        packet_count = len(self.ddos_detection[dst_ip])
        if packet_count > 100:  # Threshold for DDoS
            self._create_alert(
                alert_type="ddos",
                severity="critical",
                source_ip=packet.src_ip,
                description=f"Potential DDoS attack: {packet_count} packets to {dst_ip} in last minute",
                details={
                    'target_ip': dst_ip,
                    'packet_count': packet_count,
                    'source_ip': packet.src_ip,
                    'time_window': '1 minute'
                }
            )
            metrics.increment('ddos_attacks_detected')
    
    def _create_alert(self, alert_type: str, severity: str, source_ip: str, 
                      description: str, details: Dict[str, Any]):
        """Create a security alert
        
        Args:
            alert_type: Type of alert
            severity: Severity level
            source_ip: Source IP address
            description: Alert description
            details: Additional alert details
        """
        alert = {
            'id': f"{alert_type}_{len(self.active_alerts)}",
            'type': alert_type,
            'severity': severity,
            'source_ip': source_ip,
            'description': description,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'agent_id': self.agent_id
        }
        
        self.active_alerts.append(alert)
        self.suspicious_activities.append(alert)
        
        # Mark IP as suspicious in network monitor
        self.network_monitor.mark_suspicious_ip(source_ip, f"{alert_type}: {description}")
        
        self.logger.warning(f"ALERT [{severity.upper()}] {alert_type}: {description}")
        metrics.increment(f'alerts_{severity}')
        metrics.increment('total_alerts')
    
    async def _periodic_analysis(self):
        """Perform periodic analysis of collected data"""
        while self.running:
            try:
                await asyncio.sleep(30)  # Analyze every 30 seconds
                
                # Analyze traffic patterns
                await self._analyze_traffic_patterns()
                
                # Update detection statistics
                await self._update_detection_stats()
                
            except Exception as e:
                self.logger.error(f"Error in periodic analysis: {e}")
                await asyncio.sleep(5)
    
    async def _analyze_traffic_patterns(self):
        """Analyze overall traffic patterns for anomalies"""
        try:
            # Get network statistics
            network_stats = self.network_monitor.get_connection_stats()
            
            # Analyze connection patterns
            total_connections = network_stats.get('total_connections', 0)
            active_connections = network_stats.get('active_connections', 0)
            
            # Check for unusual activity levels
            if total_connections > 1000:  # High activity threshold
                self.logger.info(f"High network activity detected: {total_connections} total connections")
                metrics.record('high_activity_periods', 1)
            
            # Analyze top connections
            top_connections = self.network_monitor.get_top_connections(5)
            for conn_data in top_connections:
                if conn_data['count'] > 100:  # High connection count
                    self.logger.warning(f"High connection count: {conn_data['connection']} ({conn_data['count']} connections)")
            
        except Exception as e:
            self.logger.error(f"Error analyzing traffic patterns: {e}")
    
    async def _update_detection_stats(self):
        """Update detection statistics and metrics"""
        try:
            # Record current state metrics
            metrics.record('active_alerts', len(self.active_alerts))
            metrics.record('suspicious_activities', len(self.suspicious_activities))
            metrics.record('monitored_ips', len(self.connection_counts))
            
            # Calculate detection rates
            total_packets = metrics.get_counter('packets_processed')
            analyzed_packets = metrics.get_counter('packets_analyzed')
            
            if total_packets > 0:
                detection_rate = analyzed_packets / total_packets
                metrics.record('detection_rate', detection_rate)
            
        except Exception as e:
            self.logger.error(f"Error updating detection stats: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old detection data"""
        while self.running:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(hours=1)
                
                # Clean up old connection counts
                old_ips = [
                    ip for ip in self.connection_counts.keys()
                    if len(self.connection_counts) > 1000  # Only clean if too many
                ]
                for ip in old_ips[:100]:  # Remove oldest 100
                    del self.connection_counts[ip]
                
                # Clean up port scan data
                for ip in list(self.port_scan_detection.keys()):
                    if len(self.port_scan_detection[ip]) > 50:
                        # Keep only recent unique ports
                        self.port_scan_detection[ip] = set(list(self.port_scan_detection[ip])[-25:])
                
                # Clean up old alerts (keep last 1000)
                if len(self.active_alerts) > 1000:
                    self.active_alerts = self.active_alerts[-1000:]
                
                metrics.increment('cleanup_cycles')
                
            except Exception as e:
                self.logger.error(f"Error in cleanup: {e}")
                await asyncio.sleep(30)
    
    async def get_report(self) -> Optional[Dict[str, Any]]:
        """Get agent status report
        
        Returns:
            Agent report dictionary
        """
        if not self.running:
            return None
        
        # Count alerts by severity
        alert_counts = Counter(alert['severity'] for alert in self.active_alerts[-100:])
        
        # Get recent suspicious activities
        recent_activities = len([
            activity for activity in self.suspicious_activities
            if datetime.fromisoformat(activity['timestamp']) > datetime.now() - timedelta(hours=1)
        ])
        
        return {
            'status': 'active',
            'agent_type': 'detection',
            'packets_analyzed': metrics.get_counter('packets_analyzed'),
            'total_alerts': len(self.active_alerts),
            'recent_activities': recent_activities,
            'alert_counts': dict(alert_counts),
            'monitored_ips': len(self.connection_counts),
            'suspicious_ips': len(self.network_monitor.suspicious_ips),
            'network_stats': self.network_monitor.get_connection_stats(),
            'detection_rate': metrics.get_latest('detection_rate') or 0.0,
            'uptime': time.time() - self.start_time
        }
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts
        
        Args:
            severity: Filter by severity level
            limit: Maximum number of alerts to return
            
        Returns:
            List of recent alerts
        """
        alerts = self.active_alerts
        
        if severity:
            alerts = [alert for alert in alerts if alert['severity'] == severity]
        
        return alerts[-limit:]
    
    def get_suspicious_ips(self) -> Set[str]:
        """Get list of suspicious IP addresses
        
        Returns:
            Set of suspicious IP addresses
        """
        return self.network_monitor.suspicious_ips.copy()
