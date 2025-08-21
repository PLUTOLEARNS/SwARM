"""Configuration management for SwARM IDS"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Configuration manager for the SwARM system"""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration
        
        Args:
            config_file: Path to configuration file. If None, uses default.yaml
        """
        self.config_data = {}
        self.config_file = config_file
        self._load_config(config_file)
    
    def _load_config(self, config_file: Optional[str] = None):
        """Load configuration from file
        
        Args:
            config_file: Path to configuration file
        """
        if config_file is None:
            config_file = "config/default.yaml"
        
        config_path = Path(config_file)
        
        if not config_path.exists():
            # Create default config if it doesn't exist
            self._create_default_config(config_path)
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config_data = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading config file {config_path}: {e}")
            self.config_data = self._get_default_config()
    
    def _create_default_config(self, config_path: Path):
        """Create default configuration file
        
        Args:
            config_path: Path where to create the config file
        """
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        default_config = self._get_default_config()
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error creating default config: {e}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values
        
        Returns:
            Default configuration dictionary
        """
        return {
            'swarm': {
                'max_agents': 10,
                'consensus_threshold': 0.7,
                'communication_interval': 5,
                'agent_timeout': 30
            },
            'detection': {
                'anomaly_threshold': 0.8,
                'signature_database': 'data/signatures.yaml',
                'ml_model_path': 'models/anomaly_detector.pkl',
                'update_interval': 60
            },
            'network': {
                'interface': 'auto',
                'capture_filter': '',
                'packet_buffer_size': 1000,
                'monitoring_enabled': True
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'logs/swarm_ids.log',
                'max_size': '10MB',
                'backup_count': 5
            },
            'database': {
                'type': 'sqlite',
                'path': 'data/swarm_ids.db',
                'backup_interval': 3600
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value
        
        Args:
            key: Configuration key (supports dot notation, e.g., 'swarm.max_agents')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """Set configuration value
        
        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def reload(self):
        """Reload configuration from file"""
        self._load_config(self.config_file)
    
    def save(self, config_file: Optional[str] = None):
        """Save configuration to file
        
        Args:
            config_file: Path to save configuration. If None, uses default.yaml
        """
        if config_file is None:
            config_file = "config/default.yaml"
        
        config_path = Path(config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving config file {config_path}: {e}")
