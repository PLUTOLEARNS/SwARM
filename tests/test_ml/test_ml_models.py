"""
Tests for ML models in SwARM IDS
"""

import pytest
import numpy as np
from datetime import datetime
import tempfile
import os

from src.ml.models import NetworkAnomalyDetector, ThreatClassifier, AdaptiveLearningEngine
from src.ml.dataset import NetworkDatasetGenerator, RealNetworkDataCollector


class TestNetworkAnomalyDetector:
    """Test the Network Anomaly Detector"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_model_path = tempfile.mktemp(suffix='.pkl')
        self.detector = NetworkAnomalyDetector(
            contamination=0.1,
            model_path=self.temp_model_path
        )
    
    def teardown_method(self):
        """Cleanup test environment"""
        if os.path.exists(self.temp_model_path):
            os.remove(self.temp_model_path)
    
    def test_feature_extraction(self):
        """Test feature extraction from network data"""
        sample_data = [{
            'packet_size': 1200,
            'src_port': 80,
            'dst_port': 443,
            'protocol': 6,
            'connection_count': 5,
            'bytes_sent': 2000,
            'bytes_received': 1500,
            'duration': 30,
            'flags': 24,
            'packets_per_second': 10,
            'unique_ports_accessed': 2,
            'time_since_last_packet': 0.1
        }]
        
        features = self.detector.extract_features(sample_data)
        
        assert features.shape == (1, 12)
        assert features[0][0] == 1200  # packet_size
        assert features[0][1] == 80    # src_port
    
    def test_training(self):
        """Test model training"""
        # Generate sample training data
        generator = NetworkDatasetGenerator()
        normal_data = generator.generate_normal_traffic(100)
        
        # Remove labels for training
        for packet in normal_data:
            if 'label' in packet:
                del packet['label']
        
        # Train the model
        metrics = self.detector.train(normal_data)
        
        assert self.detector.is_trained
        assert 'total_samples' in metrics
        assert 'anomaly_rate' in metrics
        assert metrics['total_samples'] == 100
    
    def test_anomaly_detection(self):
        """Test anomaly detection"""
        # Train with normal data first
        generator = NetworkDatasetGenerator()
        normal_data = generator.generate_normal_traffic(100)
        for packet in normal_data:
            if 'label' in packet:
                del packet['label']
        
        self.detector.train(normal_data)
        
        # Test with suspicious data
        suspicious_packet = {
            'packet_size': 60,
            'src_port': 12345,
            'dst_port': 22,
            'protocol': 6,
            'connection_count': 200,
            'bytes_sent': 100,
            'bytes_received': 50,
            'duration': 1,
            'flags': 2,
            'packets_per_second': 1000,
            'unique_ports_accessed': 50,
            'time_since_last_packet': 0.001
        }
        
        is_anomaly, confidence, analysis = self.detector.detect_anomaly(suspicious_packet)
        
        assert isinstance(is_anomaly, bool)
        assert isinstance(confidence, float)
        assert isinstance(analysis, dict)
        assert 'prediction' in analysis
        assert 'anomaly_score' in analysis
    
    def test_model_persistence(self):
        """Test saving and loading models"""
        # Train a model
        generator = NetworkDatasetGenerator()
        normal_data = generator.generate_normal_traffic(50)
        for packet in normal_data:
            if 'label' in packet:
                del packet['label']
        
        self.detector.train(normal_data)
        
        # Create new detector and load model
        new_detector = NetworkAnomalyDetector(model_path=self.temp_model_path)
        loaded = new_detector.load_model()
        
        assert loaded
        assert new_detector.is_trained


class TestThreatClassifier:
    """Test the Threat Classifier"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_model_path = tempfile.mktemp(suffix='.pkl')
        self.classifier = ThreatClassifier(model_path=self.temp_model_path)
    
    def teardown_method(self):
        """Cleanup test environment"""
        if os.path.exists(self.temp_model_path):
            os.remove(self.temp_model_path)
    
    def test_training_with_multiple_threat_types(self):
        """Test training with multiple threat types"""
        generator = NetworkDatasetGenerator()
        
        # Generate training data
        training_data, labels = generator.generate_complete_dataset()
        
        # Train the classifier
        metrics = self.classifier.train(training_data, labels)
        
        assert self.classifier.is_trained
        assert 'accuracy' in metrics
        assert 'classification_report' in metrics
        assert metrics['accuracy'] > 0.5  # Should be better than random
    
    def test_threat_classification(self):
        """Test threat classification"""
        # Generate and train with sample data
        generator = NetworkDatasetGenerator()
        training_data, labels = generator.generate_complete_dataset()
        self.classifier.train(training_data, labels)
        
        # Test classification
        ddos_packet = {
            'packet_size': 1500,
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 6,
            'connection_count': 1000,
            'unique_ports_accessed': 1,
            'packets_per_second': 500,
            'bytes_per_second': 10000,
            'connection_duration': 5,
            'failed_connections': 0,
            'syn_flag_ratio': 0.8,
            'fin_flag_ratio': 0.1,
            'rst_flag_ratio': 0.1,
            'payload_entropy': 0.4,
            'inter_arrival_time': 0.001
        }
        
        threat_type, confidence, analysis = self.classifier.classify_threat(ddos_packet)
        
        assert threat_type in self.classifier.threat_classes
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0
        assert 'predicted_threat' in analysis
        assert 'threat_probabilities' in analysis


class TestNetworkDatasetGenerator:
    """Test the dataset generator"""
    
    def setup_method(self):
        """Setup test environment"""
        self.generator = NetworkDatasetGenerator()
    
    def test_normal_traffic_generation(self):
        """Test normal traffic generation"""
        normal_data = self.generator.generate_normal_traffic(10)
        
        assert len(normal_data) == 10
        assert all('src_ip' in packet for packet in normal_data)
        assert all('dst_ip' in packet for packet in normal_data)
        assert all('timestamp' in packet for packet in normal_data)
    
    def test_attack_traffic_generation(self):
        """Test attack traffic generation"""
        port_scan_data = self.generator.generate_port_scan_traffic(5)
        ddos_data = self.generator.generate_ddos_traffic(5)
        flood_data = self.generator.generate_connection_flood_traffic(5)
        
        assert len(port_scan_data) == 5
        assert len(ddos_data) == 5
        assert len(flood_data) == 5
        
        # Check that attack patterns have appropriate characteristics
        for packet in port_scan_data:
            assert packet['unique_ports_accessed'] >= 20  # Port scans access many ports
        
        for packet in ddos_data:
            assert packet['packets_per_second'] >= 200  # DDoS has high packet rate
    
    def test_complete_dataset_generation(self):
        """Test complete dataset generation"""
        data, labels = self.generator.generate_complete_dataset()
        
        assert len(data) == len(labels)
        assert len(data) > 1000  # Should have substantial dataset
        
        # Check label distribution
        unique_labels = set(labels)
        expected_labels = {'normal', 'port_scan', 'ddos', 'connection_flood', 'malware'}
        assert unique_labels == expected_labels


class TestAdaptiveLearningEngine:
    """Test the adaptive learning engine"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_anomaly_path = tempfile.mktemp(suffix='_anomaly.pkl')
        self.temp_threat_path = tempfile.mktemp(suffix='_threat.pkl')
        
        self.anomaly_detector = NetworkAnomalyDetector(model_path=self.temp_anomaly_path)
        self.threat_classifier = ThreatClassifier(model_path=self.temp_threat_path)
        
        # Train initial models
        generator = NetworkDatasetGenerator()
        training_data, labels = generator.generate_complete_dataset()
        
        normal_data = [data for data, label in zip(training_data, labels) if label == 'normal']
        self.anomaly_detector.train(normal_data[:100])
        self.threat_classifier.train(training_data[:200], labels[:200])
        
        self.adaptive_engine = AdaptiveLearningEngine(
            self.anomaly_detector,
            self.threat_classifier
        )
    
    def teardown_method(self):
        """Cleanup test environment"""
        for path in [self.temp_anomaly_path, self.temp_threat_path]:
            if os.path.exists(path):
                os.remove(path)
    
    def test_feedback_collection(self):
        """Test feedback collection"""
        network_data = {
            'packet_size': 1200,
            'src_port': 80,
            'dst_port': 443,
            'protocol': 6,
            'connection_count': 5
        }
        
        self.adaptive_engine.add_feedback(network_data, 'normal', 'ddos')
        
        assert len(self.adaptive_engine.feedback_buffer) == 1
        assert self.adaptive_engine.feedback_buffer[0]['actual_label'] == 'normal'
        assert self.adaptive_engine.feedback_buffer[0]['predicted_label'] == 'ddos'
        assert not self.adaptive_engine.feedback_buffer[0]['correct']
    
    def test_learning_stats(self):
        """Test learning statistics"""
        # Add some feedback
        network_data = {'packet_size': 1200, 'src_port': 80}
        
        self.adaptive_engine.add_feedback(network_data, 'normal', 'normal')
        self.adaptive_engine.add_feedback(network_data, 'ddos', 'normal')
        
        stats = self.adaptive_engine.get_learning_stats()
        
        assert 'feedback_samples' in stats
        assert 'accuracy' in stats
        assert 'last_retrain' in stats
        assert stats['feedback_samples'] == 2
        assert stats['accuracy'] == 0.5  # 1 correct out of 2


class TestRealNetworkDataCollector:
    """Test real network data collection"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_storage = tempfile.mktemp(suffix='.csv')
        self.collector = RealNetworkDataCollector(self.temp_storage)
    
    def teardown_method(self):
        """Cleanup test environment"""
        if os.path.exists(self.temp_storage):
            os.remove(self.temp_storage)
    
    def test_data_collection(self):
        """Test collecting network packets"""
        packet_data = {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'packet_size': 1200,
            'protocol': 'TCP'
        }
        
        self.collector.collect_packet(packet_data, 'normal')
        
        assert len(self.collector.collected_data) == 1
        assert self.collector.collected_data[0]['label'] == 'normal'
    
    def test_data_persistence(self):
        """Test saving collected data"""
        packet_data = {
            'src_ip': '192.168.1.100',
            'packet_size': 1200
        }
        
        self.collector.collect_packet(packet_data, 'port_scan')
        self.collector.save_collected_data()
        
        # Verify file was created
        assert os.path.exists(self.temp_storage)
        
        # Test loading data back
        data, labels = self.collector.get_labeled_data()
        assert len(data) == 1
        assert labels[0] == 'port_scan'
