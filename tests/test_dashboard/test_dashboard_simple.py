"""
Simple tests for SwarmDashboard functionality
"""

import tempfile
import os
import pytest
from src.dashboard.dashboard import SwarmDashboard
from src.database.database import SwarmDatabase

class TestSwarmDashboard:
    """Test SwarmDashboard basic functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_db_path = tempfile.mktemp(suffix='.db')
        self.db = SwarmDatabase(self.temp_db_path)
    
    def teardown_method(self):
        """Cleanup test environment"""
        if os.path.exists(self.temp_db_path):
            os.unlink(self.temp_db_path)
    
    def test_dashboard_creation(self):
        """Test dashboard can be created"""
        dashboard = SwarmDashboard(self.db, port=5555)
        assert dashboard is not None
        assert hasattr(dashboard, 'app')
    
    def test_dashboard_has_app(self):
        """Test dashboard has Flask app"""
        dashboard = SwarmDashboard(self.db, port=5555)
        assert hasattr(dashboard, 'app')
        assert dashboard.app is not None

class TestDashboardUtilities:
    """Test dashboard utility functions"""
    
    def test_alert_serialization(self):
        """Test alert serialization for JSON API"""
        temp_db_path = tempfile.mktemp(suffix='.db')
        db = SwarmDatabase(temp_db_path)
        
        alert_id = db.save_alert(
            threat_type='serialization_test',
            severity='medium',
            source_ip='1.2.3.4',
            confidence=0.75
        )
        
        alerts = db.get_recent_alerts(limit=1)
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'serialization_test'
        
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)
    
    def test_statistics_aggregation(self):
        """Test statistics aggregation for dashboard display"""
        temp_db_path = tempfile.mktemp(suffix='.db')
        db = SwarmDatabase(temp_db_path)
        
        for i in range(3):
            db.save_network_statistics(
                packets_analyzed=1000 * (i + 1),
                anomalies_detected=50 * (i + 1),
                threats_classified=10
            )
        
        stats = db.get_network_statistics(limit=3)
        assert len(stats) == 3
        
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)
