
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
