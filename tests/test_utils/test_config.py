"""Tests for configuration management"""

import pytest
import tempfile
import yaml
from pathlib import Path
from src.utils.config import Config


class TestConfig:
    """Test cases for Config class"""
    
    def test_default_config_creation(self):
        """Test that default configuration is created correctly"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "test_config.yaml"
            config = Config(str(config_file))
            
            # Check that config file was created
            assert config_file.exists()
            
            # Check default values
            assert config.get('swarm.max_agents') == 10
            assert config.get('swarm.consensus_threshold') == 0.7
            assert config.get('detection.anomaly_threshold') == 0.8
            assert config.get('logging.level') == 'INFO'
    
    def test_get_with_dot_notation(self):
        """Test getting values with dot notation"""
        config = Config()
        
        # Test nested access
        assert config.get('swarm.max_agents') is not None
        assert config.get('logging.level') is not None
        
        # Test default values
        assert config.get('nonexistent.key', 'default') == 'default'
        assert config.get('swarm.nonexistent', 42) == 42
    
    def test_set_configuration(self):
        """Test setting configuration values"""
        config = Config()
        
        # Set a simple value
        config.set('test.value', 123)
        assert config.get('test.value') == 123
        
        # Set nested value
        config.set('deeply.nested.value', 'test')
        assert config.get('deeply.nested.value') == 'test'
    
    def test_load_custom_config(self):
        """Test loading custom configuration file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "custom_config.yaml"
            
            # Create custom config
            custom_config = {
                'swarm': {'max_agents': 20},
                'custom': {'value': 'test'}
            }
            
            with open(config_file, 'w') as f:
                yaml.dump(custom_config, f)
            
            config = Config(str(config_file))
            
            assert config.get('swarm.max_agents') == 20
            assert config.get('custom.value') == 'test'
    
    def test_save_configuration(self):
        """Test saving configuration to file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "save_test.yaml"
            config = Config()
            
            # Modify configuration
            config.set('test.save', 'saved_value')
            
            # Save configuration
            config.save(str(config_file))
            
            # Load and verify
            with open(config_file, 'r') as f:
                saved_config = yaml.safe_load(f)
            
            assert saved_config['test']['save'] == 'saved_value'
    
    def test_reload_configuration(self):
        """Test reloading configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "reload_test.yaml"
            
            # Create initial config
            initial_config = {'test': {'value': 'initial'}}
            with open(config_file, 'w') as f:
                yaml.dump(initial_config, f)
            
            config = Config(str(config_file))
            assert config.get('test.value') == 'initial'
            
            # Modify file externally
            modified_config = {'test': {'value': 'modified'}}
            with open(config_file, 'w') as f:
                yaml.dump(modified_config, f)
            
            # Reload and verify
            config.reload()
            assert config.get('test.value') == 'modified'
    
    @pytest.mark.parametrize("key,expected", [
        ('swarm.max_agents', 10),
        ('detection.anomaly_threshold', 0.8),
        ('logging.level', 'INFO'),
        ('network.monitoring_enabled', True)
    ])
    def test_default_values(self, key, expected):
        """Test specific default configuration values"""
        config = Config()
        assert config.get(key) == expected
