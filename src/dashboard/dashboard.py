"""
Real-time web dashboard for SwARM IDS
Provides visualization of threats, alerts, and system status
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import json
from datetime import datetime, timedelta
from typing import Dict, List
import logging
import threading
import time
from pathlib import Path
import os

# Dashboard static files
DASHBOARD_DIR = Path(__file__).parent
STATIC_DIR = DASHBOARD_DIR / "static"
TEMPLATES_DIR = DASHBOARD_DIR / "templates"

logger = logging.getLogger(__name__)

class SwarmDashboard:
    """Real-time web dashboard for SwARM IDS"""
    
    def __init__(self, database, host: str = "127.0.0.1", port: int = 5000):
        self.database = database
        self.host = host
        self.port = port
        
        # Create Flask app
        self.app = Flask(__name__, 
                        static_folder=str(STATIC_DIR),
                        template_folder=str(TEMPLATES_DIR))
        self.app.config['SECRET_KEY'] = 'swarm_ids_dashboard_2025'
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Dashboard state
        self.connected_clients = 0
        self.last_update = datetime.now()
        self.update_thread = None
        self.running = False
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio_events()
        
        # Create static files and templates
        self._create_dashboard_files()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            return render_template('dashboard.html')
        
        @self.app.route('/api/alerts')
        def get_alerts():
            limit = request.args.get('limit', 100, type=int)
            severity = request.args.get('severity', None)
            since_hours = request.args.get('since_hours', 24, type=int)
            
            since = datetime.now() - timedelta(hours=since_hours)
            alerts = self.database.get_alerts(limit=limit, severity=severity, since=since)
            
            # Convert to JSON serializable format
            alerts_data = []
            for alert in alerts:
                alert_dict = {
                    'id': alert.id,
                    'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
                    'agent_id': alert.agent_id,
                    'alert_type': alert.alert_type,
                    'severity': alert.severity,
                    'source_ip': alert.source_ip,
                    'destination_ip': alert.destination_ip,
                    'source_port': alert.source_port,
                    'destination_port': alert.destination_port,
                    'protocol': alert.protocol,
                    'description': alert.description,
                    'ml_confidence': alert.ml_confidence,
                    'ml_prediction': alert.ml_prediction,
                    'false_positive': alert.false_positive,
                    'acknowledged': alert.acknowledged,
                    'resolved': alert.resolved
                }
                alerts_data.append(alert_dict)
            
            return jsonify(alerts_data)
        
        @self.app.route('/api/statistics')
        def get_statistics():
            since_hours = request.args.get('since_hours', 24, type=int)
            since = datetime.now() - timedelta(hours=since_hours)
            
            # Get alert statistics
            alert_stats = self.database.get_alert_statistics(since=since)
            
            # Get network statistics
            network_stats = self.database.get_network_statistics(since=since, limit=1)
            latest_network = network_stats[0] if network_stats else None
            
            # Get database stats
            db_stats = self.database.get_database_stats()
            
            return jsonify({
                'alert_statistics': alert_stats,
                'network_statistics': {
                    'total_packets': latest_network.total_packets if latest_network else 0,
                    'total_bytes': latest_network.total_bytes if latest_network else 0,
                    'unique_ips': latest_network.unique_ips if latest_network else 0,
                    'suspicious_ips': latest_network.suspicious_ips if latest_network else 0,
                    'timestamp': latest_network.timestamp.isoformat() if latest_network and latest_network.timestamp else None
                },
                'database_statistics': db_stats,
                'system_status': {
                    'connected_clients': self.connected_clients,
                    'last_update': self.last_update.isoformat(),
                    'dashboard_uptime': str(datetime.now() - self.last_update)
                }
            })
        
        @self.app.route('/api/alerts/<int:alert_id>/update', methods=['POST'])
        def update_alert(alert_id):
            data = request.get_json()
            
            acknowledged = data.get('acknowledged')
            resolved = data.get('resolved')
            false_positive = data.get('false_positive')
            
            self.database.update_alert_status(
                alert_id=alert_id,
                acknowledged=acknowledged,
                resolved=resolved,
                false_positive=false_positive
            )
            
            # Emit update to all clients
            self.socketio.emit('alert_updated', {
                'alert_id': alert_id,
                'acknowledged': acknowledged,
                'resolved': resolved,
                'false_positive': false_positive
            })
            
            return jsonify({'success': True})
        
        @self.app.route('/api/network_timeline')
        def get_network_timeline():
            hours = request.args.get('hours', 24, type=int)
            since = datetime.now() - timedelta(hours=hours)
            
            network_stats = self.database.get_network_statistics(since=since, limit=hours*6)  # 10-minute intervals
            
            timeline_data = []
            for stats in reversed(network_stats):  # Reverse to get chronological order
                timeline_data.append({
                    'timestamp': stats.timestamp.isoformat() if stats.timestamp else None,
                    'total_packets': stats.total_packets,
                    'suspicious_ips': stats.suspicious_ips,
                    'alerts_generated': stats.alerts_generated
                })
            
            return jsonify(timeline_data)
    
    def _setup_socketio_events(self):
        """Setup SocketIO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            self.connected_clients += 1
            logger.info(f"Client connected. Total clients: {self.connected_clients}")
            emit('status', {'connected_clients': self.connected_clients})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            self.connected_clients -= 1
            logger.info(f"Client disconnected. Total clients: {self.connected_clients}")
        
        @self.socketio.on('request_update')
        def handle_update_request():
            # Send latest statistics
            emit('statistics_update', self._get_real_time_stats())
    
    def _get_real_time_stats(self) -> Dict:
        """Get real-time statistics for dashboard updates"""
        # Get recent alerts (last hour)
        recent_alerts = self.database.get_alerts(limit=50, since=datetime.now() - timedelta(hours=1))
        
        # Get latest network stats
        network_stats = self.database.get_network_statistics(limit=1)
        latest_network = network_stats[0] if network_stats else None
        
        return {
            'recent_alerts_count': len(recent_alerts),
            'critical_alerts': len([a for a in recent_alerts if a.severity == 'CRITICAL']),
            'high_alerts': len([a for a in recent_alerts if a.severity == 'HIGH']),
            'medium_alerts': len([a for a in recent_alerts if a.severity == 'MEDIUM']),
            'total_packets': latest_network.total_packets if latest_network else 0,
            'suspicious_ips': latest_network.suspicious_ips if latest_network else 0,
            'timestamp': datetime.now().isoformat()
        }
    
    def broadcast_new_alert(self, alert_data: Dict):
        """Broadcast new alert to all connected clients"""
        if self.connected_clients > 0:
            self.socketio.emit('new_alert', alert_data)
    
    def start_background_updates(self):
        """Start background thread for real-time updates"""
        if self.update_thread and self.update_thread.is_alive():
            return
        
        self.running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        logger.info("Dashboard background updates started")
    
    def stop_background_updates(self):
        """Stop background updates"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        logger.info("Dashboard background updates stopped")
    
    def _update_loop(self):
        """Background update loop"""
        while self.running:
            try:
                if self.connected_clients > 0:
                    stats = self._get_real_time_stats()
                    self.socketio.emit('statistics_update', stats)
                    self.last_update = datetime.now()
                
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                logger.error(f"Error in dashboard update loop: {e}")
                time.sleep(10)
    
    def run(self, debug: bool = False):
        """Run the dashboard server"""
        self.start_background_updates()
        try:
            logger.info(f"Starting SwARM IDS Dashboard on http://{self.host}:{self.port}")
            self.socketio.run(self.app, host=self.host, port=self.port, debug=debug)
        finally:
            self.stop_background_updates()
    
    def _create_dashboard_files(self):
        """Create static files and templates for the dashboard"""
        # Create directories
        STATIC_DIR.mkdir(parents=True, exist_ok=True)
        TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create main dashboard HTML template
        dashboard_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SwARM IDS Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='dashboard.css') }}" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <header class="d-flex justify-content-between align-items-center py-3 mb-4 border-bottom">
            <h1 class="h3">🛡️ SwARM Intrusion Detection System</h1>
            <div class="status-indicators">
                <span id="connection-status" class="badge bg-success">Connected</span>
                <span id="last-update" class="text-muted small">Last update: Never</span>
            </div>
        </header>

        <!-- Statistics Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card text-white bg-danger">
                    <div class="card-body">
                        <h5 class="card-title">Critical Alerts</h5>
                        <h2 id="critical-count">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-warning">
                    <div class="card-body">
                        <h5 class="card-title">High Priority</h5>
                        <h2 id="high-count">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-info">
                    <div class="card-body">
                        <h5 class="card-title">Medium Priority</h5>
                        <h2 id="medium-count">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-secondary">
                    <div class="card-body">
                        <h5 class="card-title">Suspicious IPs</h5>
                        <h2 id="suspicious-ips">0</h2>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Alert Timeline</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="alertChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Network Traffic</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Alerts Table -->
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Recent Alerts</h5>
                        <div>
                            <select id="severity-filter" class="form-select form-select-sm">
                                <option value="">All Severities</option>
                                <option value="CRITICAL">Critical</option>
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                            </select>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Severity</th>
                                        <th>Type</th>
                                        <th>Source IP</th>
                                        <th>Description</th>
                                        <th>ML Confidence</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="alerts-table">
                                    <!-- Alerts will be populated here -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="{{ url_for('static', filename='dashboard.js') }}"></script>
</body>
</html>'''
        
        with open(TEMPLATES_DIR / 'dashboard.html', 'w', encoding='utf-8') as f:
            f.write(dashboard_html)
        
        # Create CSS file
        dashboard_css = '''
body {
    background-color: #f8f9fa;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.status-indicators {
    display: flex;
    align-items: center;
    gap: 10px;
}

.card {
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    border: 1px solid rgba(0, 0, 0, 0.125);
}

.alert-row {
    cursor: pointer;
}

.alert-row:hover {
    background-color: #f8f9fa;
}

.severity-badge {
    font-weight: bold;
}

.severity-CRITICAL {
    background-color: #dc3545 !important;
}

.severity-HIGH {
    background-color: #fd7e14 !important;
}

.severity-MEDIUM {
    background-color: #0dcaf0 !important;
}

.severity-LOW {
    background-color: #6c757d !important;
}

.ml-confidence {
    border-radius: 10px;
    padding: 2px 8px;
    font-size: 0.8em;
}

.confidence-high {
    background-color: #d4edda;
    color: #155724;
}

.confidence-medium {
    background-color: #fff3cd;
    color: #856404;
}

.confidence-low {
    background-color: #f8d7da;
    color: #721c24;
}

.chart-container {
    position: relative;
    height: 300px;
}

#connection-status.disconnected {
    background-color: #dc3545 !important;
}

.new-alert {
    animation: highlightAlert 2s ease-in-out;
}

@keyframes highlightAlert {
    0% { background-color: #fff3cd; }
    100% { background-color: transparent; }
}
'''
        
        with open(STATIC_DIR / 'dashboard.css', 'w', encoding='utf-8') as f:
            f.write(dashboard_css)
        
        # Create JavaScript file
        dashboard_js = '''
class SwarmDashboard {
    constructor() {
        this.socket = io();
        this.charts = {};
        this.alerts = [];
        
        this.initializeCharts();
        this.setupEventListeners();
        this.loadInitialData();
    }
    
    initializeCharts() {
        // Alert Timeline Chart
        const alertCtx = document.getElementById('alertChart').getContext('2d');
        this.charts.alerts = new Chart(alertCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Alerts per Hour',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Traffic Chart
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        this.charts.traffic = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets per Minute',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    setupEventListeners() {
        // Socket events
        this.socket.on('connect', () => {
            console.log('Connected to SwARM IDS Dashboard');
            document.getElementById('connection-status').textContent = 'Connected';
            document.getElementById('connection-status').className = 'badge bg-success';
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from dashboard');
            document.getElementById('connection-status').textContent = 'Disconnected';
            document.getElementById('connection-status').className = 'badge bg-danger disconnected';
        });
        
        this.socket.on('statistics_update', (data) => {
            this.updateStatistics(data);
        });
        
        this.socket.on('new_alert', (alertData) => {
            this.addNewAlert(alertData);
        });
        
        this.socket.on('alert_updated', (updateData) => {
            this.updateAlertInTable(updateData);
        });
        
        // Filter change
        document.getElementById('severity-filter').addEventListener('change', () => {
            this.loadAlerts();
        });
        
        // Auto-refresh
        setInterval(() => {
            this.socket.emit('request_update');
        }, 10000); // Request update every 10 seconds
    }
    
    async loadInitialData() {
        await this.loadAlerts();
        await this.loadStatistics();
        await this.loadNetworkTimeline();
    }
    
    async loadAlerts() {
        const severity = document.getElementById('severity-filter').value;
        const params = new URLSearchParams({
            limit: '50',
            since_hours: '24'
        });
        
        if (severity) {
            params.append('severity', severity);
        }
        
        try {
            const response = await fetch(`/api/alerts?${params}`);
            this.alerts = await response.json();
            this.renderAlertsTable();
        } catch (error) {
            console.error('Error loading alerts:', error);
        }
    }
    
    async loadStatistics() {
        try {
            const response = await fetch('/api/statistics?since_hours=24');
            const data = await response.json();
            this.updateStatisticsDisplay(data);
        } catch (error) {
            console.error('Error loading statistics:', error);
        }
    }
    
    async loadNetworkTimeline() {
        try {
            const response = await fetch('/api/network_timeline?hours=24');
            const data = await response.json();
            this.updateTrafficChart(data);
        } catch (error) {
            console.error('Error loading network timeline:', error);
        }
    }
    
    updateStatistics(data) {
        document.getElementById('critical-count').textContent = data.critical_alerts || 0;
        document.getElementById('high-count').textContent = data.high_alerts || 0;
        document.getElementById('medium-count').textContent = data.medium_alerts || 0;
        document.getElementById('suspicious-ips').textContent = data.suspicious_ips || 0;
        
        const updateTime = new Date(data.timestamp).toLocaleTimeString();
        document.getElementById('last-update').textContent = `Last update: ${updateTime}`;
    }
    
    updateStatisticsDisplay(data) {
        const alertStats = data.alert_statistics;
        const networkStats = data.network_statistics;
        
        // Update counters
        document.getElementById('critical-count').textContent = alertStats.severity_counts.CRITICAL || 0;
        document.getElementById('high-count').textContent = alertStats.severity_counts.HIGH || 0;
        document.getElementById('medium-count').textContent = alertStats.severity_counts.MEDIUM || 0;
        document.getElementById('suspicious-ips').textContent = networkStats.suspicious_ips || 0;
    }
    
    renderAlertsTable() {
        const tbody = document.getElementById('alerts-table');
        tbody.innerHTML = '';
        
        this.alerts.forEach(alert => {
            const row = this.createAlertRow(alert);
            tbody.appendChild(row);
        });
    }
    
    createAlertRow(alert) {
        const row = document.createElement('tr');
        row.className = 'alert-row';
        row.dataset.alertId = alert.id;
        
        const timestamp = new Date(alert.timestamp).toLocaleString();
        const confidence = Math.round(alert.ml_confidence * 100);
        const confidenceClass = confidence > 80 ? 'confidence-high' : confidence > 50 ? 'confidence-medium' : 'confidence-low';
        
        row.innerHTML = `
            <td>${timestamp}</td>
            <td><span class="badge severity-${alert.severity}">${alert.severity}</span></td>
            <td>${alert.alert_type}</td>
            <td>${alert.source_ip}</td>
            <td>${alert.description}</td>
            <td><span class="ml-confidence ${confidenceClass}">${confidence}%</span></td>
            <td>
                ${alert.resolved ? '<span class="badge bg-success">Resolved</span>' : 
                  alert.acknowledged ? '<span class="badge bg-warning">Acknowledged</span>' : 
                  '<span class="badge bg-secondary">New</span>'}
                ${alert.false_positive ? '<span class="badge bg-danger">False Positive</span>' : ''}
            </td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-primary" onclick="dashboard.acknowledgeAlert(${alert.id})">Ack</button>
                    <button class="btn btn-outline-success" onclick="dashboard.resolveAlert(${alert.id})">Resolve</button>
                    <button class="btn btn-outline-danger" onclick="dashboard.markFalsePositive(${alert.id})">FP</button>
                </div>
            </td>
        `;
        
        return row;
    }
    
    updateTrafficChart(data) {
        const labels = data.map(item => new Date(item.timestamp).toLocaleTimeString());
        const packets = data.map(item => item.total_packets);
        
        this.charts.traffic.data.labels = labels;
        this.charts.traffic.data.datasets[0].data = packets;
        this.charts.traffic.update();
    }
    
    addNewAlert(alertData) {
        // Add to beginning of alerts array
        this.alerts.unshift(alertData);
        
        // Re-render table
        this.renderAlertsTable();
        
        // Highlight the new row
        const newRow = document.querySelector(`[data-alert-id="${alertData.id}"]`);
        if (newRow) {
            newRow.classList.add('new-alert');
        }
        
        // Show notification
        this.showNotification(`New ${alertData.severity} alert: ${alertData.alert_type}`, 'warning');
    }
    
    updateAlertInTable(updateData) {
        const row = document.querySelector(`[data-alert-id="${updateData.alert_id}"]`);
        if (row) {
            // Update the alert in our data
            const alertIndex = this.alerts.findIndex(a => a.id === updateData.alert_id);
            if (alertIndex !== -1) {
                Object.assign(this.alerts[alertIndex], updateData);
                
                // Re-render just this row
                const newRow = this.createAlertRow(this.alerts[alertIndex]);
                row.replaceWith(newRow);
            }
        }
    }
    
    async acknowledgeAlert(alertId) {
        await this.updateAlert(alertId, { acknowledged: true });
    }
    
    async resolveAlert(alertId) {
        await this.updateAlert(alertId, { resolved: true });
    }
    
    async markFalsePositive(alertId) {
        await this.updateAlert(alertId, { false_positive: true });
    }
    
    async updateAlert(alertId, updates) {
        try {
            const response = await fetch(`/api/alerts/${alertId}/update`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updates)
            });
            
            if (response.ok) {
                this.showNotification('Alert updated successfully', 'success');
            } else {
                this.showNotification('Error updating alert', 'danger');
            }
        } catch (error) {
            console.error('Error updating alert:', error);
            this.showNotification('Error updating alert', 'danger');
        }
    }
    
    showNotification(message, type) {
        // Simple notification system
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 1050; min-width: 300px;';
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new SwarmDashboard();
});
'''
        
        with open(STATIC_DIR / 'dashboard.js', 'w', encoding='utf-8') as f:
            f.write(dashboard_js)
        
        logger.info("Dashboard static files created successfully")
