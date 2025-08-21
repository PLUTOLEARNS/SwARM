"""
Real network intrusion dataset loader for SwARM IDS
Downloads and processes publicly available cybersecurity datasets
"""

import pandas as pd
import numpy as np
import requests
import zipfile
import os
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import pickle

logger = logging.getLogger(__name__)

class RealDatasetLoader:
    """Loads real network intrusion datasets from online sources"""
    
    def __init__(self, data_dir: str = "data/datasets"):
        """Initialize dataset loader
        
        Args:
            data_dir: Directory to store downloaded datasets
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Available datasets
        self.datasets = {
            'nsl-kdd': {
                'name': 'NSL-KDD Dataset',
                'train_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
                'test_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt',
                'features_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/Field%20Names.txt',
                'description': 'NSL-KDD is an enhanced version of KDD Cup 99 dataset',
                'columns': [
                    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
                    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
                    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
                ]
            },
            'cicids2017': {
                'name': 'CIC-IDS2017 Dataset',
                'description': 'Canadian Institute for Cybersecurity Intrusion Detection Dataset',
                'note': 'Large dataset - requires manual download from https://www.unb.ca/cic/datasets/ids-2017.html'
            },
            'unsw-nb15': {
                'name': 'UNSW-NB15 Dataset',
                'train_url': 'https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download',
                'test_url': 'https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download',
                'description': 'University of New South Wales Network-Based Dataset'
            }
        }
        
        self.preprocessors = {}
        
    def list_available_datasets(self) -> Dict[str, str]:
        """List all available datasets"""
        return {name: info['description'] for name, info in self.datasets.items()}
    
    def download_nsl_kdd(self) -> bool:
        """Download NSL-KDD dataset"""
        try:
            dataset_info = self.datasets['nsl-kdd']
            train_file = self.data_dir / 'nsl_kdd_train.txt'
            test_file = self.data_dir / 'nsl_kdd_test.txt'
            
            if not train_file.exists():
                logger.info("Downloading NSL-KDD training data...")
                response = requests.get(dataset_info['train_url'])
                response.raise_for_status()
                with open(train_file, 'wb') as f:
                    f.write(response.content)
                logger.info(f"Training data saved to {train_file}")
            
            if not test_file.exists():
                logger.info("Downloading NSL-KDD test data...")
                response = requests.get(dataset_info['test_url'])
                response.raise_for_status()
                with open(test_file, 'wb') as f:
                    f.write(response.content)
                logger.info(f"Test data saved to {test_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error downloading NSL-KDD dataset: {e}")
            return False
    
    def load_nsl_kdd(self, use_cache: bool = True) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Load and preprocess NSL-KDD dataset
        
        Args:
            use_cache: Use cached preprocessed data if available
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        cache_file = self.data_dir / 'nsl_kdd_processed.pkl'
        
        if use_cache and cache_file.exists():
            logger.info("Loading cached NSL-KDD dataset...")
            with open(cache_file, 'rb') as f:
                return pickle.load(f)
        
        # Download if not exists
        if not self.download_nsl_kdd():
            raise RuntimeError("Failed to download NSL-KDD dataset")
        
        logger.info("Processing NSL-KDD dataset...")
        
        # Load data
        columns = self.datasets['nsl-kdd']['columns']
        train_file = self.data_dir / 'nsl_kdd_train.txt'
        test_file = self.data_dir / 'nsl_kdd_test.txt'
        
        df_train = pd.read_csv(train_file, names=columns, header=None)
        df_test = pd.read_csv(test_file, names=columns, header=None)
        
        # Preprocess data
        X_train, y_train = self._preprocess_nsl_kdd(df_train)
        X_test, y_test = self._preprocess_nsl_kdd(df_test)
        
        # Cache processed data
        processed_data = (X_train, X_test, y_train, y_test)
        with open(cache_file, 'wb') as f:
            pickle.dump(processed_data, f)
        
        logger.info(f"NSL-KDD dataset loaded: Train={X_train.shape}, Test={X_test.shape}")
        
        return processed_data
    
    def _preprocess_nsl_kdd(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Preprocess NSL-KDD dataframe"""
        # Remove difficulty column
        if 'difficulty' in df.columns:
            df = df.drop('difficulty', axis=1)
        
        # Separate features and labels
        X = df.drop('attack_type', axis=1)
        y = df['attack_type']
        
        # Encode categorical features
        categorical_columns = ['protocol_type', 'service', 'flag']
        
        for col in categorical_columns:
            if col in X.columns:
                if col not in self.preprocessors:
                    self.preprocessors[col] = LabelEncoder()
                    X[col] = self.preprocessors[col].fit_transform(X[col].astype(str))
                else:
                    # Handle unknown categories by mapping them to a default value
                    X_col = X[col].astype(str)
                    known_classes = set(self.preprocessors[col].classes_)
                    X_col = X_col.apply(lambda x: x if x in known_classes else self.preprocessors[col].classes_[0])
                    X[col] = self.preprocessors[col].transform(X_col)
        
        # Convert labels to binary (normal vs attack)
        y_binary = (y != 'normal').astype(int)
        
        # Scale numerical features
        if 'scaler' not in self.preprocessors:
            self.preprocessors['scaler'] = StandardScaler()
            X_scaled = self.preprocessors['scaler'].fit_transform(X)
        else:
            X_scaled = self.preprocessors['scaler'].transform(X)
        
        return X_scaled, np.array(y_binary)
    
    def get_attack_types_mapping(self) -> Dict[str, str]:
        """Get mapping of attack types to categories"""
        return {
            'normal': 'normal',
            'apache2': 'dos',
            'back': 'dos',
            'land': 'dos',
            'neptune': 'dos',
            'mailbomb': 'dos',
            'pod': 'dos',
            'processtable': 'dos',
            'smurf': 'dos',
            'teardrop': 'dos',
            'udpstorm': 'dos',
            'worm': 'dos',
            'ipsweep': 'probe',
            'mscan': 'probe',
            'nmap': 'probe',
            'portsweep': 'probe',
            'saint': 'probe',
            'satan': 'probe',
            'buffer_overflow': 'u2r',
            'loadmodule': 'u2r',
            'perl': 'u2r',
            'rootkit': 'u2r',
            'ftp_write': 'r2l',
            'guess_passwd': 'r2l',
            'imap': 'r2l',
            'multihop': 'r2l',
            'phf': 'r2l',
            'spy': 'r2l',
            'warezclient': 'r2l',
            'warezmaster': 'r2l',
            'sendmail': 'r2l',
            'named': 'r2l',
            'snmpgetattack': 'r2l',
            'snmpguess': 'r2l',
            'xlock': 'r2l',
            'xsnoop': 'r2l',
            'httptunnel': 'r2l'
        }
    
    def download_sample_datasets(self) -> bool:
        """Download sample datasets for testing"""
        try:
            # Create a small sample dataset for quick testing
            sample_file = self.data_dir / 'sample_network_data.csv'
            
            if not sample_file.exists():
                logger.info("Creating sample network dataset...")
                
                # Generate sample data
                np.random.seed(42)
                n_samples = 1000
                
                data = {
                    'duration': np.random.exponential(2, n_samples),
                    'src_bytes': np.random.lognormal(8, 2, n_samples),
                    'dst_bytes': np.random.lognormal(6, 3, n_samples),
                    'count': np.random.poisson(10, n_samples),
                    'srv_count': np.random.poisson(5, n_samples),
                    'serror_rate': np.random.beta(1, 10, n_samples),
                    'rerror_rate': np.random.beta(1, 15, n_samples),
                    'same_srv_rate': np.random.beta(5, 2, n_samples),
                    'diff_srv_rate': np.random.beta(2, 5, n_samples),
                    'dst_host_count': np.random.poisson(20, n_samples),
                    'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_samples, p=[0.7, 0.25, 0.05]),
                    'service': np.random.choice(['http', 'ftp', 'smtp', 'telnet', 'ssh'], n_samples),
                    'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTR'], n_samples, p=[0.6, 0.2, 0.1, 0.1]),
                }
                
                # Add attack labels (20% attacks)
                attack_indices = np.random.choice(n_samples, size=int(0.2 * n_samples), replace=False)
                labels = ['normal'] * n_samples
                for idx in attack_indices:
                    labels[idx] = np.random.choice(['dos', 'probe', 'u2r', 'r2l'])
                
                data['attack_type'] = labels
                
                df = pd.DataFrame(data)
                df.to_csv(sample_file, index=False)
                logger.info(f"Sample dataset created at {sample_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating sample dataset: {e}")
            return False
    
    def get_dataset_info(self, dataset_name: str) -> Dict:
        """Get information about a specific dataset"""
        if dataset_name not in self.datasets:
            raise ValueError(f"Unknown dataset: {dataset_name}")
        
        info = self.datasets[dataset_name].copy()
        
        # Add file existence information
        if dataset_name == 'nsl-kdd':
            train_file = self.data_dir / 'nsl_kdd_train.txt'
            test_file = self.data_dir / 'nsl_kdd_test.txt'
            cache_file = self.data_dir / 'nsl_kdd_processed.pkl'
            
            info['files_exist'] = {
                'train': train_file.exists(),
                'test': test_file.exists(),
                'processed_cache': cache_file.exists()
            }
        
        return info
    
    def benchmark_model_performance(self, model, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Benchmark model performance on real dataset
        
        Args:
            model: Trained ML model
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Performance metrics
        """
        from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
        
        logger.info("Benchmarking model performance...")
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        # Use safe metric calculation with zero_division parameter
        precision_val = precision_score(y_test, y_pred, zero_division=0)
        recall_val = recall_score(y_test, y_pred, zero_division=0)
        f1_val = f1_score(y_test, y_pred, zero_division=0)
        
        # Calculate confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Handle different confusion matrix shapes
        if cm.size == 4:
            tn, fp, fn, tp = cm.ravel()
        else:
            # Handle cases where only one class is present
            tp = fp = tn = fn = 0
            if len(cm) > 0:
                tp = cm[1, 1] if cm.shape[0] > 1 and cm.shape[1] > 1 else 0
                tn = cm[0, 0] if cm.shape[0] > 0 and cm.shape[1] > 0 else 0
                fp = cm[0, 1] if cm.shape[0] > 0 and cm.shape[1] > 1 else 0
                fn = cm[1, 0] if cm.shape[0] > 1 and cm.shape[1] > 0 else 0
        
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision_val),
            'recall': float(recall_val),
            'f1_score': float(f1_val),
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'total_samples': len(y_test),
            'attack_samples': int(np.sum(y_test)),
            'normal_samples': int(len(y_test) - np.sum(y_test)),
            'detection_rate': float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0,
            'false_alarm_rate': float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        }
        
        logger.info(f"Model Performance:")
        logger.info(f"  Accuracy: {metrics['accuracy']:.3f}")
        logger.info(f"  Precision: {metrics['precision']:.3f}")
        logger.info(f"  Recall: {metrics['recall']:.3f}")
        logger.info(f"  F1-Score: {metrics['f1_score']:.3f}")
        logger.info(f"  Detection Rate: {metrics['detection_rate']:.3f}")
        logger.info(f"  False Alarm Rate: {metrics['false_alarm_rate']:.3f}")
        
        return metrics
