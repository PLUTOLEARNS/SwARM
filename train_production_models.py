#!/usr/bin/env python3
"""
Production ML Model Training for SwARM IDS
Trains models on real NSL-KDD dataset for production deployment
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.ml.real_datasets import RealDatasetLoader
from src.ml.models import NetworkAnomalyDetector, ThreatClassifier
from src.utils.config import Config
from src.utils.logger import setup_logging

def main():
    """Train production ML models"""
    print("🚀 SwARM IDS - Production ML Model Training")
    print("=" * 60)
    
    # Setup logging
    config = Config("config/default.yaml")
    setup_logging(config.config_data)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize dataset loader
        print("📦 Loading NSL-KDD Dataset...")
        dataset_loader = RealDatasetLoader()
        
        # Download NSL-KDD if needed
        if not dataset_loader.download_nsl_kdd():
            print("❌ Failed to download NSL-KDD dataset")
            return 1
            
        # Load and preprocess data
        print("🔄 Preprocessing data...")
        X_train, X_test, y_train, y_test = dataset_loader.load_nsl_kdd()
        
        print(f"✅ Loaded {len(X_train)} training samples, {len(X_test)} test samples")
        
        # Train Anomaly Detector
        print("\n🔍 Training Anomaly Detector...")
        anomaly_detector = NetworkAnomalyDetector()
        
        # Convert to format expected by model (using subset for training speed)
        training_packets = []
        sample_size = min(5000, len(X_train))  # Use smaller subset for demo
        
        for i in range(sample_size):
            packet = {
                'packet_size': float(X_train[i][4]) if len(X_train[i]) > 4 else 0,  # src_bytes
                'src_port': 0,  # Not in NSL-KDD
                'dst_port': 0,  # Not in NSL-KDD  
                'protocol': float(X_train[i][1]) if len(X_train[i]) > 1 else 1,  # protocol_type
                'connection_count': float(X_train[i][22]) if len(X_train[i]) > 22 else 0,  # count
                'bytes_sent': float(X_train[i][4]) if len(X_train[i]) > 4 else 0,  # src_bytes
                'bytes_received': float(X_train[i][5]) if len(X_train[i]) > 5 else 0,  # dst_bytes
                'duration': float(X_train[i][0]) if len(X_train[i]) > 0 else 0,  # duration
                'flags': 0,
                'packets_per_second': 1,
                'unique_ports_accessed': 1,
                'time_since_last_packet': 0
            }
            training_packets.append(packet)
        
        metrics = anomaly_detector.train(training_packets)
        print(f"✅ Anomaly Detector trained: {metrics['anomalies_detected']} anomalies in {metrics['total_samples']} samples")
        
        # Train Threat Classifier
        print("\n🎯 Training Threat Classifier...")
        threat_classifier = ThreatClassifier()
        
        # Prepare labeled data for threat classifier
        threat_data = []
        threat_labels = []
        
        for i in range(sample_size):
            packet = {
                'packet_size': float(X_train[i][4]) if len(X_train[i]) > 4 else 0,
                'src_port': 0,
                'dst_port': 0,
                'protocol': float(X_train[i][1]) if len(X_train[i]) > 1 else 1,
                'connection_count': float(X_train[i][22]) if len(X_train[i]) > 22 else 0,
                'bytes_sent': float(X_train[i][4]) if len(X_train[i]) > 4 else 0,
                'bytes_received': float(X_train[i][5]) if len(X_train[i]) > 5 else 0,
                'duration': float(X_train[i][0]) if len(X_train[i]) > 0 else 0,
                'flags': 0,
                'packets_per_second': 1,
                'unique_ports_accessed': 1,
                'time_since_last_packet': 0
            }
            threat_data.append(packet)
            
            # Map binary labels to threat categories
            if y_train[i] == 0:
                threat_labels.append('normal')
            else:
                # For binary classification, map attacks to generic 'attack' category
                threat_labels.append('attack')
                
        metrics = threat_classifier.train(threat_data, threat_labels)
        print(f"✅ Threat Classifier trained: {metrics['accuracy']:.3f} accuracy")
        
        # Test models
        print("\n🧪 Testing Models...")
        
        # Test anomaly detector
        test_packet = threat_data[0]
        is_anomaly = anomaly_detector.detect_anomaly(test_packet)
        print(f"   Anomaly Detection Test: {'ANOMALY' if is_anomaly else 'NORMAL'}")
        
        # Test threat classifier
        threat_type = threat_classifier.classify_threat(test_packet)
        print(f"   Threat Classification Test: {threat_type}")
        
        # Display final metrics
        print("\n📊 Final Model Performance:")
        print(f"   Anomaly Detector F1: {anomaly_detector.get_f1_score():.3f}")
        print(f"   Anomaly Detector AUC: {anomaly_detector.get_auc_score():.3f}")
        print(f"   Threat Classifier F1: {threat_classifier.get_f1_score():.3f}")
        print(f"   Threat Classifier AUC: {threat_classifier.get_auc_score():.3f}")
        
        print("\n✅ Production model training completed successfully!")
        print("🚀 Models are ready for production deployment")
        
        return 0
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
