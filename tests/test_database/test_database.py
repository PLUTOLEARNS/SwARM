"""
Simple tests for SwarmDatabase functionality
"""

import tempfile
import os
import pytest
from src.database.database import SwarmDatabase, Alert, NetworkStatistics, MLModelPerformance

class TestSwarmDatabase:
    """Test SwarmDatabase basic functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_db_path = tempfile.mktemp(suffix='.db')
        self.db = SwarmDatabase(self.temp_db_path)
    
    def teardown_method(self):
        """Cleanup test environment"""
        if os.path.exists(self.temp_db_path):
            os.unlink(self.temp_db_path)
    
    def test_database_initialization(self):
        """Test database creation and table setup"""
        assert os.path.exists(self.temp_db_path)
        alerts = self.db.get_recent_alerts(limit=1)
        assert isinstance(alerts, list)
    
    def test_alert_creation_and_retrieval(self):
        """Test creating and retrieving alerts"""
        alert_id = self.db.save_alert(
            threat_type='ddos',
            severity='high',
            source_ip='192.168.1.100',
            confidence=0.95,
            description='DDoS attack detected'
        )
        assert isinstance(alert_id, int)
        assert alert_id > 0
        
        alerts = self.db.get_recent_alerts(limit=1)
        assert len(alerts) == 1
        
        alert = alerts[0]
        assert alert.alert_type == 'ddos'
        assert alert.severity == 'high'
        assert alert.source_ip == '192.168.1.100'
    
    def test_network_statistics_storage(self):
        """Test storing network statistics"""
        stats_id = self.db.save_network_statistics(
            packets_analyzed=1000,
            anomalies_detected=25,
            threats_classified=5
        )
        assert isinstance(stats_id, int)
        assert stats_id > 0
        
        stats = self.db.get_network_statistics(limit=1)
        assert len(stats) == 1
        assert stats[0].total_packets == 1000
    
    def test_ml_performance_tracking(self):
        """Test ML model performance tracking"""
        perf_id = self.db.save_ml_performance(
            model_type='anomaly_detector',
            accuracy=0.92,
            precision=0.89,
            recall=0.95,
            f1_score=0.92,
            training_samples=5000
        )
        assert isinstance(perf_id, int)
        assert perf_id > 0
