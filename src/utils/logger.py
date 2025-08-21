"""Logging utilities for SwARM IDS"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Dict, Any


def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """Setup logging configuration
    
    Args:
        config: Logging configuration dictionary
        
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_file = config.get('file', 'logs/swarm_ids.log')
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure logging
    level = getattr(logging, config.get('level', 'INFO').upper())
    format_str = config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create formatter
    formatter = logging.Formatter(format_str)
    
    # Create logger
    logger = logging.getLogger('swarm_ids')
    logger.setLevel(level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    max_size = _parse_size(config.get('max_size', '10MB'))
    backup_count = config.get('backup_count', 5)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_size,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


def _parse_size(size_str: str) -> int:
    """Parse size string to bytes
    
    Args:
        size_str: Size string like '10MB', '1GB', etc.
        
    Returns:
        Size in bytes
    """
    size_str = size_str.upper().strip()
    
    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4
    }
    
    for suffix, multiplier in multipliers.items():
        if size_str.endswith(suffix):
            try:
                number = float(size_str[:-len(suffix)])
                return int(number * multiplier)
            except ValueError:
                break
    
    # Default to 10MB if parsing fails
    return 10 * 1024 * 1024


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(f'swarm_ids.{name}')
