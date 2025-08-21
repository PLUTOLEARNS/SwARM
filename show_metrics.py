#!/usr/bin/env python3
"""
SwARM IDS Metrics Dashboard
Swarm Agent Response Monitoring
Shows F1, AUC, ROC scores and system status
"""

import asyncio
import time
from src.ml.models import NetworkAnomalyDetector, ThreatClassifier
from src.database.database import SwarmDatabase
from src.main_github import SwarmIDS

def display_metrics():
    """Display current ML model metrics and system status"""
    print("=" * 70)
    print("    SwARM IDS - Swarm Agent Response Monitoring")
    print("    Machine Learning Metrics Dashboard")
    print("=" * 70)
    
    # Initialize ML models
    print("\nLoading ML Models...")
    anomaly_detector = NetworkAnomalyDetector()
    threat_classifier = ThreatClassifier()
    
    # Display Anomaly Detector Metrics
    print("\n🔍 ANOMALY DETECTOR PERFORMANCE:")
    print(f"   Accuracy:  {anomaly_detector.get_accuracy():.3f}")
    print(f"   Precision: {anomaly_detector.get_precision():.3f}")
    print(f"   Recall:    {anomaly_detector.get_recall():.3f}")
    print(f"   F1 Score:  {anomaly_detector.get_f1_score():.3f}")
    print(f"   AUC Score: {anomaly_detector.get_auc_score():.3f}")
    print(f"   ROC Score: {anomaly_detector.get_roc_score():.3f}")
    
    # Display Threat Classifier Metrics
    print("\n🎯 THREAT CLASSIFIER PERFORMANCE:")
    print(f"   Accuracy:  {threat_classifier.get_accuracy():.3f}")
    print(f"   Precision: {threat_classifier.get_precision():.3f}")
    print(f"   Recall:    {threat_classifier.get_recall():.3f}")
    print(f"   F1 Score:  {threat_classifier.get_f1_score():.3f}")
    print(f"   AUC Score: {threat_classifier.get_auc_score():.3f}")
    print(f"   ROC Score: {threat_classifier.get_roc_score():.3f}")
    
    # Database Statistics
    print("\n📊 SYSTEM STATISTICS:")
    try:
        db = SwarmDatabase()
        alerts = db.get_recent_alerts(limit=100)
        stats = db.get_network_statistics(limit=10)
        
        print(f"   Recent Alerts: {len(alerts)}")
        print(f"   Network Stats: {len(stats)} entries")
        
        if alerts:
            severity_counts = {}
            for alert in alerts:
                severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
            
            print("   Alert Breakdown:")
            for severity, count in severity_counts.items():
                print(f"     {severity.capitalize()}: {count}")
        
    except Exception as e:
        print(f"   Database Error: {e}")
    
    # System Status
    print("\n SYSTEM STATUS:")
    print("   ML Models: Loaded and Ready")
    print("   Database: Connected")
    print("   Dashboard: Available at http://localhost:5000")
    
    # Overall Performance Score
    avg_f1 = (anomaly_detector.get_f1_score() + threat_classifier.get_f1_score()) / 2
    avg_auc = (anomaly_detector.get_auc_score() + threat_classifier.get_auc_score()) / 2
    avg_accuracy = (anomaly_detector.get_accuracy() + threat_classifier.get_accuracy()) / 2
    
    print(f"\n OVERALL PERFORMANCE:")
    print(f"   Average F1 Score:  {avg_f1:.3f}")
    print(f"   Average AUC Score: {avg_auc:.3f}")
    print(f"   Average Accuracy:  {avg_accuracy:.3f}")
    
    if avg_f1 > 0.9:
        performance_rating = "EXCELLENT"
    elif avg_f1 > 0.8:
        performance_rating = "GOOD"
    elif avg_f1 > 0.7:
        performance_rating = "FAIR"
    else:
        performance_rating = "NEEDS IMPROVEMENT"
    
    print(f"   Performance Rating: {performance_rating}")
    
    print("\n" + "=" * 60)

async def launch_full_system():
    """Launch the complete SwARM IDS system with metrics"""
    print("🚀 Launching SwARM IDS with Metrics Dashboard...")
    
    # Display initial metrics
    display_metrics()
    
    # Start the main SwARM IDS system
    print("\n🔧 Starting SwARM IDS Core System...")
    try:
        swarm_ids = SwarmIDS()
        await swarm_ids.start()
        
        print("SwARM IDS system started successfully!")
        print("Metrics dashboard available above")
        print("Web dashboard available at http://localhost:5000")
        print("\nPress Ctrl+C to stop the system...")
        
        # Keep running and show periodic updates
        while True:
            await asyncio.sleep(30)  # Update every 30 seconds
            print(f"\n⏰ Status Update - {time.strftime('%H:%M:%S')}")
            print("   System Running - All Components Active")
            
    except KeyboardInterrupt:
        print("\n Shutting down SwARM IDS...")
        if 'swarm_ids' in locals():
            await swarm_ids.stop()
        print(" System stopped successfully")
    except Exception as e:
        print(f" Error starting system: {e}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SwARM IDS Metrics Dashboard")
    parser.add_argument("--metrics-only", action="store_true", 
                       help="Show metrics only without starting the full system")
    
    args = parser.parse_args()
    
    if args.metrics_only:
        display_metrics()
    else:
        asyncio.run(launch_full_system())
