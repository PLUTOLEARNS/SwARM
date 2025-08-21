"""
Training dataset generator for SwARM IDS
Creates synthetic and real network data for ML training
"""

import numpy as np
import pandas as pd
import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class NetworkDatasetGenerator:
    """Generate training datasets for machine learning models"""
    
    def __init__(self, output_dir: str = "data/training"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_normal_traffic(self, num_samples: int = 1000) -> List[Dict]:
        """Generate normal network traffic patterns"""
        normal_traffic = []
        
        for i in range(num_samples):
            # Common ports for normal traffic
            common_ports = [80, 443, 53, 22, 25, 143, 993, 995, 110, 8080]
            
            packet = {
                'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 3600)),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'src_port': random.choice(range(1024, 65535)),
                'dst_port': random.choice(common_ports),
                'protocol': random.choice([1, 6, 17]),  # ICMP, TCP, UDP
                'packet_size': random.normalvariate(1200, 300),
                'connection_count': random.randint(1, 5),
                'bytes_sent': random.normalvariate(2000, 500),
                'bytes_received': random.normalvariate(1800, 400),
                'duration': random.normalvariate(30, 10),
                'flags': random.choice([2, 16, 24]),  # SYN, ACK, PSH+ACK
                'packets_per_second': random.normalvariate(10, 3),
                'unique_ports_accessed': random.randint(1, 3),
                'time_since_last_packet': random.normalvariate(0.1, 0.05),
                'failed_connections': 0,
                'syn_flag_ratio': random.uniform(0.1, 0.3),
                'fin_flag_ratio': random.uniform(0.1, 0.3),
                'rst_flag_ratio': random.uniform(0.0, 0.1),
                'payload_entropy': random.uniform(0.5, 0.8),
                'inter_arrival_time': random.normalvariate(0.1, 0.02),
                'bytes_per_second': random.normalvariate(1000, 200),
                'connection_duration': random.normalvariate(60, 15),
                'label': 'normal'
            }
            normal_traffic.append(packet)
        
        logger.info(f"Generated {num_samples} normal traffic samples")
        return normal_traffic
    
    def generate_port_scan_traffic(self, num_samples: int = 200) -> List[Dict]:
        """Generate port scanning attack patterns"""
        port_scan_traffic = []
        
        for i in range(num_samples):
            # Port scan characteristics
            packet = {
                'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 3600)),
                'src_ip': f"172.16.{random.randint(1, 255)}.{random.randint(1, 254)}",
                'dst_ip': f"192.168.1.{random.randint(1, 254)}",
                'src_port': random.choice(range(1024, 65535)),
                'dst_port': random.randint(1, 65535),  # Random ports being scanned
                'protocol': 6,  # TCP
                'packet_size': random.normalvariate(60, 10),  # Small packets
                'connection_count': random.randint(50, 200),  # Many connections
                'bytes_sent': random.normalvariate(100, 20),
                'bytes_received': random.normalvariate(50, 10),
                'duration': random.normalvariate(1, 0.5),  # Short duration
                'flags': 2,  # SYN flag
                'packets_per_second': random.normalvariate(100, 20),  # High rate
                'unique_ports_accessed': random.randint(20, 100),  # Many ports
                'time_since_last_packet': random.normalvariate(0.01, 0.005),  # Fast
                'failed_connections': random.randint(80, 100),  # Many failures
                'syn_flag_ratio': random.uniform(0.8, 1.0),  # High SYN ratio
                'fin_flag_ratio': random.uniform(0.0, 0.1),
                'rst_flag_ratio': random.uniform(0.7, 0.9),  # High RST ratio
                'payload_entropy': random.uniform(0.1, 0.3),  # Low entropy
                'inter_arrival_time': random.normalvariate(0.001, 0.0005),
                'bytes_per_second': random.normalvariate(50, 10),
                'connection_duration': random.normalvariate(1, 0.2),
                'label': 'port_scan'
            }
            port_scan_traffic.append(packet)
        
        logger.info(f"Generated {num_samples} port scan samples")
        return port_scan_traffic
    
    def generate_ddos_traffic(self, num_samples: int = 200) -> List[Dict]:
        """Generate DDoS attack patterns"""
        ddos_traffic = []
        
        for i in range(num_samples):
            # DDoS characteristics
            packet = {
                'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 3600)),
                'src_ip': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
                'dst_ip': "192.168.1.100",  # Single target
                'src_port': random.choice(range(1024, 65535)),
                'dst_port': random.choice([80, 443, 53]),  # Common targets
                'protocol': random.choice([6, 17]),  # TCP, UDP
                'packet_size': random.normalvariate(1500, 200),  # Large packets
                'connection_count': random.randint(500, 2000),  # Many connections
                'bytes_sent': random.normalvariate(5000, 1000),
                'bytes_received': random.normalvariate(100, 50),
                'duration': random.normalvariate(5, 2),
                'flags': random.choice([2, 16, 24]),
                'packets_per_second': random.normalvariate(500, 100),  # Very high rate
                'unique_ports_accessed': random.randint(1, 3),  # Few ports
                'time_since_last_packet': random.normalvariate(0.002, 0.001),  # Very fast
                'failed_connections': random.randint(0, 10),
                'syn_flag_ratio': random.uniform(0.6, 0.9),
                'fin_flag_ratio': random.uniform(0.0, 0.2),
                'rst_flag_ratio': random.uniform(0.0, 0.3),
                'payload_entropy': random.uniform(0.2, 0.6),
                'inter_arrival_time': random.normalvariate(0.001, 0.0005),
                'bytes_per_second': random.normalvariate(10000, 2000),
                'connection_duration': random.normalvariate(10, 3),
                'label': 'ddos'
            }
            ddos_traffic.append(packet)
        
        logger.info(f"Generated {num_samples} DDoS samples")
        return ddos_traffic
    
    def generate_connection_flood_traffic(self, num_samples: int = 200) -> List[Dict]:
        """Generate connection flooding attack patterns"""
        flood_traffic = []
        
        for i in range(num_samples):
            packet = {
                'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 3600)),
                'src_ip': f"10.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
                'dst_ip': f"192.168.1.{random.randint(1, 254)}",
                'src_port': random.choice(range(1024, 65535)),
                'dst_port': random.choice([80, 443, 22, 25]),
                'protocol': 6,  # TCP
                'packet_size': random.normalvariate(400, 100),
                'connection_count': random.randint(300, 1000),  # Many connections
                'bytes_sent': random.normalvariate(500, 100),
                'bytes_received': random.normalvariate(200, 50),
                'duration': random.normalvariate(60, 20),
                'flags': random.choice([2, 16, 24]),
                'packets_per_second': random.normalvariate(200, 50),
                'unique_ports_accessed': random.randint(1, 5),
                'time_since_last_packet': random.normalvariate(0.005, 0.002),
                'failed_connections': random.randint(50, 200),
                'syn_flag_ratio': random.uniform(0.7, 0.9),
                'fin_flag_ratio': random.uniform(0.1, 0.3),
                'rst_flag_ratio': random.uniform(0.3, 0.6),
                'payload_entropy': random.uniform(0.3, 0.7),
                'inter_arrival_time': random.normalvariate(0.003, 0.001),
                'bytes_per_second': random.normalvariate(2000, 500),
                'connection_duration': random.normalvariate(30, 10),
                'label': 'connection_flood'
            }
            flood_traffic.append(packet)
        
        logger.info(f"Generated {num_samples} connection flood samples")
        return flood_traffic
    
    def generate_malware_traffic(self, num_samples: int = 150) -> List[Dict]:
        """Generate malware communication patterns"""
        malware_traffic = []
        
        for i in range(num_samples):
            packet = {
                'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 3600)),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
                'src_port': random.choice(range(1024, 65535)),
                'dst_port': random.choice([8080, 9999, 6667, 443, 80]),  # Suspicious ports
                'protocol': 6,  # TCP
                'packet_size': random.normalvariate(800, 200),
                'connection_count': random.randint(5, 20),
                'bytes_sent': random.normalvariate(3000, 800),
                'bytes_received': random.normalvariate(1000, 300),
                'duration': random.normalvariate(300, 100),  # Long duration
                'flags': random.choice([16, 24]),  # ACK, PSH+ACK
                'packets_per_second': random.normalvariate(5, 2),  # Low rate
                'unique_ports_accessed': random.randint(1, 3),
                'time_since_last_packet': random.normalvariate(5, 2),  # Periodic
                'failed_connections': random.randint(0, 5),
                'syn_flag_ratio': random.uniform(0.1, 0.3),
                'fin_flag_ratio': random.uniform(0.1, 0.3),
                'rst_flag_ratio': random.uniform(0.0, 0.1),
                'payload_entropy': random.uniform(0.8, 1.0),  # High entropy (encrypted)
                'inter_arrival_time': random.normalvariate(10, 5),
                'bytes_per_second': random.normalvariate(200, 50),
                'connection_duration': random.normalvariate(600, 200),
                'label': 'malware'
            }
            malware_traffic.append(packet)
        
        logger.info(f"Generated {num_samples} malware samples")
        return malware_traffic
    
    def generate_complete_dataset(self) -> Tuple[List[Dict], List[str]]:
        """Generate a complete balanced dataset"""
        logger.info("Generating complete training dataset...")
        
        # Generate all types of traffic
        normal = self.generate_normal_traffic(2000)
        port_scan = self.generate_port_scan_traffic(400)
        ddos = self.generate_ddos_traffic(400)
        connection_flood = self.generate_connection_flood_traffic(400)
        malware = self.generate_malware_traffic(300)
        
        # Combine all data
        all_data = normal + port_scan + ddos + connection_flood + malware
        labels = [packet['label'] for packet in all_data]
        
        # Remove label from packet data
        for packet in all_data:
            del packet['label']
        
        # Shuffle the data
        combined = list(zip(all_data, labels))
        random.shuffle(combined)
        all_data, labels = zip(*combined)
        
        logger.info(f"Generated complete dataset with {len(all_data)} samples")
        logger.info(f"Label distribution: {pd.Series(labels).value_counts().to_dict()}")
        
        return list(all_data), list(labels)
    
    def save_dataset(self, data: List[Dict], labels: List[str], filename: str = "training_dataset.csv"):
        """Save dataset to CSV file"""
        # Convert to DataFrame
        df = pd.DataFrame(data)
        df['label'] = labels
        
        # Save to CSV
        filepath = self.output_dir / filename
        df.to_csv(filepath, index=False)
        
        logger.info(f"Dataset saved to {filepath}")
        logger.info(f"Dataset shape: {df.shape}")
        
        return filepath
    
    def load_dataset(self, filename: str = "training_dataset.csv") -> Tuple[List[Dict], List[str]]:
        """Load dataset from CSV file"""
        filepath = self.output_dir / filename
        
        if not filepath.exists():
            logger.error(f"Dataset file not found: {filepath}")
            return [], []
        
        df = pd.read_csv(filepath)
        labels = df['label'].tolist()
        
        # Remove label column and convert to dict list
        df = df.drop('label', axis=1)
        data = df.to_dict('records')
        
        logger.info(f"Loaded dataset from {filepath}")
        logger.info(f"Dataset shape: {df.shape}")
        
        return data, labels

class RealNetworkDataCollector:
    """Collect and label real network data for training"""
    
    def __init__(self, storage_path: str = "data/real_network_data.csv"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.collected_data = []
        
    def collect_packet(self, packet_data: Dict, label: str = 'unlabeled'):
        """Collect a real network packet with optional label"""
        packet_data['label'] = label
        packet_data['collection_timestamp'] = datetime.now().isoformat()
        self.collected_data.append(packet_data)
        
        # Auto-save every 100 packets
        if len(self.collected_data) % 100 == 0:
            self.save_collected_data()
    
    def save_collected_data(self):
        """Save collected real data to file"""
        if not self.collected_data:
            return
        
        df = pd.DataFrame(self.collected_data)
        
        # Append to existing file if it exists
        if self.storage_path.exists():
            df.to_csv(self.storage_path, mode='a', header=False, index=False)
        else:
            df.to_csv(self.storage_path, index=False)
        
        logger.info(f"Saved {len(self.collected_data)} real network samples to {self.storage_path}")
        self.collected_data.clear()
    
    def get_labeled_data(self) -> Tuple[List[Dict], List[str]]:
        """Get labeled real network data for training"""
        if not self.storage_path.exists():
            logger.warning("No real network data file found")
            return [], []
        
        df = pd.read_csv(self.storage_path)
        
        # Filter out unlabeled data
        labeled_df = df[df['label'] != 'unlabeled']
        
        if labeled_df.empty:
            logger.warning("No labeled real network data found")
            return [], []
        
        labels = labeled_df['label'].tolist()
        data = labeled_df.drop(['label', 'collection_timestamp'], axis=1).to_dict('records')
        
        logger.info(f"Retrieved {len(data)} labeled real network samples")
        return data, labels
