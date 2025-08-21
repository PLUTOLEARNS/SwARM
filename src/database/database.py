"""
Database models and persistence for SwARM IDS
Stores alerts, threat data, network statistics, and ML model performance
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Alert data structure"""
    id: Optional[int] = None
    timestamp: Optional[datetime] = None
    agent_id: str = ""
    alert_type: str = ""
    severity: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""
    description: str = ""
    raw_data: str = ""
    ml_confidence: float = 0.0
    ml_prediction: str = ""
    false_positive: bool = False
    acknowledged: bool = False
    resolved: bool = False
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class NetworkStatistics:
    """Network statistics data structure"""
    id: Optional[int] = None
    timestamp: Optional[datetime] = None
    total_packets: int = 0
    total_bytes: int = 0
    unique_ips: int = 0
    unique_ports: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    suspicious_ips: int = 0
    alerts_generated: int = 0
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class MLModelPerformance:
    """ML model performance metrics"""
    id: Optional[int] = None
    timestamp: Optional[datetime] = None
    model_name: str = ""
    model_version: str = ""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    training_samples: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class SwarmDatabase:
    """SQLite database for SwARM IDS data persistence"""
    
    def __init__(self, db_path: str = "data/swarm_ids.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    description TEXT,
                    raw_data TEXT,
                    ml_confidence REAL DEFAULT 0.0,
                    ml_prediction TEXT,
                    false_positive BOOLEAN DEFAULT FALSE,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    resolved BOOLEAN DEFAULT FALSE,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Network statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_packets INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    unique_ips INTEGER DEFAULT 0,
                    unique_ports INTEGER DEFAULT 0,
                    tcp_packets INTEGER DEFAULT 0,
                    udp_packets INTEGER DEFAULT 0,
                    icmp_packets INTEGER DEFAULT 0,
                    suspicious_ips INTEGER DEFAULT 0,
                    alerts_generated INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # ML model performance table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ml_performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    model_version TEXT,
                    accuracy REAL DEFAULT 0.0,
                    precision REAL DEFAULT 0.0,
                    recall REAL DEFAULT 0.0,
                    f1_score REAL DEFAULT 0.0,
                    training_samples INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    false_negatives INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Network traffic table (for ML training data)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    packet_size INTEGER,
                    connection_count INTEGER,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    duration REAL,
                    flags TEXT,
                    packets_per_second REAL,
                    unique_ports_accessed INTEGER,
                    label TEXT,
                    ml_features TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat intelligence table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL DEFAULT 0.0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    alert_count INTEGER DEFAULT 0,
                    blocked BOOLEAN DEFAULT FALSE,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_network_stats_timestamp ON network_statistics(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ml_performance_timestamp ON ml_performance(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON network_traffic(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intelligence(ip_address)")
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def insert_alert(self, alert: Alert) -> int:
        """Insert a new alert into the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts (
                    timestamp, agent_id, alert_type, severity, source_ip,
                    destination_ip, source_port, destination_port, protocol,
                    description, raw_data, ml_confidence, ml_prediction
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp.isoformat() if alert.timestamp else datetime.now().isoformat(),
                alert.agent_id,
                alert.alert_type,
                alert.severity,
                alert.source_ip,
                alert.destination_ip,
                alert.source_port,
                alert.destination_port,
                alert.protocol,
                alert.description,
                alert.raw_data,
                alert.ml_confidence,
                alert.ml_prediction
            ))
            
            alert_id = cursor.lastrowid or 0
            conn.commit()
            
            logger.debug(f"Inserted alert {alert_id}: {alert.alert_type} from {alert.source_ip}")
            return alert_id
    
    def save_alert(self, threat_type: str, severity: str, source_ip: str, 
                   confidence: float, destination_ip: str = "", description: str = "",
                   agent_id: str = "system") -> int:
        """Save alert with simplified parameters for test compatibility"""
        alert = Alert(
            agent_id=agent_id,
            alert_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            ml_confidence=confidence
        )
        return self.insert_alert(alert)
    
    def get_alerts(self, limit: int = 100, severity: Optional[str] = None, 
                   since: Optional[datetime] = None, source_ip: Optional[str] = None) -> List[Alert]:
        """Retrieve alerts with optional filtering"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if since:
                query += " AND timestamp >= ?"
                params.append(since.isoformat())
            
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            alerts = []
            for row in rows:
                alert = Alert(
                    id=row['id'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    agent_id=row['agent_id'],
                    alert_type=row['alert_type'],
                    severity=row['severity'],
                    source_ip=row['source_ip'],
                    destination_ip=row['destination_ip'],
                    source_port=row['source_port'],
                    destination_port=row['destination_port'],
                    protocol=row['protocol'],
                    description=row['description'],
                    raw_data=row['raw_data'],
                    ml_confidence=row['ml_confidence'],
                    ml_prediction=row['ml_prediction'],
                    false_positive=bool(row['false_positive']),
                    acknowledged=bool(row['acknowledged']),
                    resolved=bool(row['resolved'])
                )
                alerts.append(alert)
            
            return alerts
    
    def get_recent_alerts(self, limit: int = 100) -> List[Alert]:
        """Get recent alerts for test compatibility"""
        return self.get_alerts(limit=limit)
    
    def update_alert_status(self, alert_id: int, acknowledged: Optional[bool] = None, 
                           resolved: Optional[bool] = None, false_positive: Optional[bool] = None):
        """Update alert status flags"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if acknowledged is not None:
                updates.append("acknowledged = ?")
                params.append(acknowledged)
            
            if resolved is not None:
                updates.append("resolved = ?")
                params.append(resolved)
            
            if false_positive is not None:
                updates.append("false_positive = ?")
                params.append(false_positive)
            
            if updates:
                query = f"UPDATE alerts SET {', '.join(updates)} WHERE id = ?"
                params.append(alert_id)
                
                cursor.execute(query, params)
                conn.commit()
                
                logger.debug(f"Updated alert {alert_id} status")
    
    def insert_network_statistics(self, stats: NetworkStatistics) -> int:
        """Insert network statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO network_statistics (
                    timestamp, total_packets, total_bytes, unique_ips,
                    unique_ports, tcp_packets, udp_packets, icmp_packets,
                    suspicious_ips, alerts_generated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                stats.timestamp.isoformat() if stats.timestamp else datetime.now().isoformat(),
                stats.total_packets,
                stats.total_bytes,
                stats.unique_ips,
                stats.unique_ports,
                stats.tcp_packets,
                stats.udp_packets,
                stats.icmp_packets,
                stats.suspicious_ips,
                stats.alerts_generated
            ))
            
            stats_id = cursor.lastrowid or 0
            conn.commit()
            
            logger.debug(f"Inserted network statistics {stats_id}")
            return stats_id
    
    def save_network_statistics(self, packets_analyzed: int, anomalies_detected: int,
                               threats_classified: int, processing_time: float = 0.0,
                               false_positives: int = 0, true_positives: int = 0) -> int:
        """Save network statistics with simplified parameters for test compatibility"""
        stats = NetworkStatistics(
            total_packets=packets_analyzed,
            alerts_generated=anomalies_detected + threats_classified,
            suspicious_ips=threats_classified
        )
        return self.insert_network_statistics(stats)
    
    def get_network_statistics(self, since: Optional[datetime] = None, limit: int = 100) -> List[NetworkStatistics]:
        """Retrieve network statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if since:
                cursor.execute("""
                    SELECT * FROM network_statistics 
                    WHERE timestamp >= ? 
                    ORDER BY timestamp DESC LIMIT ?
                """, (since.isoformat(), limit))
            else:
                cursor.execute("""
                    SELECT * FROM network_statistics 
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
            
            stats_list = []
            for row in rows:
                stats = NetworkStatistics(
                    id=row['id'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    total_packets=row['total_packets'],
                    total_bytes=row['total_bytes'],
                    unique_ips=row['unique_ips'],
                    unique_ports=row['unique_ports'],
                    tcp_packets=row['tcp_packets'],
                    udp_packets=row['udp_packets'],
                    icmp_packets=row['icmp_packets'],
                    suspicious_ips=row['suspicious_ips'],
                    alerts_generated=row['alerts_generated']
                )
                stats_list.append(stats)
            
            return stats_list
    
    def insert_ml_performance(self, performance: MLModelPerformance) -> int:
        """Insert ML model performance metrics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO ml_performance (
                    timestamp, model_name, model_version, accuracy,
                    precision, recall, f1_score, training_samples,
                    false_positives, false_negatives
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                performance.timestamp.isoformat() if performance.timestamp else datetime.now().isoformat(),
                performance.model_name,
                performance.model_version,
                performance.accuracy,
                performance.precision,
                performance.recall,
                performance.f1_score,
                performance.training_samples,
                performance.false_positives,
                performance.false_negatives
            ))
            
            perf_id = cursor.lastrowid or 0
            conn.commit()
            
            logger.debug(f"Inserted ML performance metrics {perf_id}")
            return perf_id
    
    def save_ml_performance(self, model_type: str, accuracy: float, precision: float,
                           recall: float, f1_score: float, training_samples: int,
                           test_samples: int = 0) -> int:
        """Save ML performance with simplified parameters for test compatibility"""
        performance = MLModelPerformance(
            model_name=model_type,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            training_samples=training_samples
        )
        return self.insert_ml_performance(performance)
    
    def get_alert_statistics(self, since: Optional[datetime] = None) -> Dict:
        """Get alert statistics and trends"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            since_clause = "WHERE timestamp >= ?" if since else ""
            params = [since.isoformat()] if since else []
            
            # Total alerts by severity
            cursor.execute(f"""
                SELECT severity, COUNT(*) as count 
                FROM alerts {since_clause}
                GROUP BY severity
            """, params)
            severity_counts = dict(cursor.fetchall())
            
            # Alerts by type
            cursor.execute(f"""
                SELECT alert_type, COUNT(*) as count 
                FROM alerts {since_clause}
                GROUP BY alert_type
            """, params)
            type_counts = dict(cursor.fetchall())
            
            # Top source IPs
            cursor.execute(f"""
                SELECT source_ip, COUNT(*) as count 
                FROM alerts {since_clause}
                GROUP BY source_ip 
                ORDER BY count DESC LIMIT 10
            """, params)
            top_ips = dict(cursor.fetchall())
            
            # False positive rate
            cursor.execute(f"""
                SELECT 
                    COUNT(CASE WHEN false_positive = 1 THEN 1 END) as false_positives,
                    COUNT(*) as total_alerts
                FROM alerts {since_clause}
            """, params)
            fp_data = cursor.fetchone()
            fp_rate = fp_data['false_positives'] / fp_data['total_alerts'] if fp_data['total_alerts'] > 0 else 0
            
            return {
                'severity_counts': severity_counts,
                'type_counts': type_counts,
                'top_source_ips': top_ips,
                'false_positive_rate': fp_rate,
                'total_alerts': fp_data['total_alerts']
            }
    
    def cleanup_old_data(self, days_to_keep: int = 30):
        """Clean up old data to manage database size"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Clean old network traffic data (keep alerts and stats longer)
            cursor.execute("""
                DELETE FROM network_traffic 
                WHERE timestamp < ?
            """, (cutoff_date.isoformat(),))
            
            traffic_deleted = cursor.rowcount
            
            # Clean very old resolved alerts
            old_cutoff = datetime.now() - timedelta(days=days_to_keep * 2)
            cursor.execute("""
                DELETE FROM alerts 
                WHERE timestamp < ? AND resolved = 1
            """, (old_cutoff.isoformat(),))
            
            alerts_deleted = cursor.rowcount
            conn.commit()
            
            logger.info(f"Cleaned up {traffic_deleted} old traffic records and {alerts_deleted} old resolved alerts")
    
    def get_database_stats(self) -> Dict:
        """Get database size and record counts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Record counts
            tables = ['alerts', 'network_statistics', 'ml_performance', 'network_traffic', 'threat_intelligence']
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                stats[f"{table}_count"] = cursor.fetchone()['count']
            
            # Database size
            stats['database_size_mb'] = self.db_path.stat().st_size / (1024 * 1024)
            
            return stats
    
    def close(self):
        """Close database connection - for test compatibility"""
        # SQLite connections are closed automatically in context managers
        # This method exists for test compatibility
        pass
