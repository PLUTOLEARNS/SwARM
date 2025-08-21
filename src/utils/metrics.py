"""Metrics collection and monitoring utilities"""

import time
import threading
from typing import Dict, Any, Optional
from collections import defaultdict, deque


class MetricsCollector:
    """Collect and manage system metrics"""
    
    def __init__(self, max_history: int = 1000):
        """Initialize metrics collector
        
        Args:
            max_history: Maximum number of historical values to keep
        """
        self.max_history = max_history
        self.metrics = defaultdict(lambda: deque(maxlen=max_history))
        self.counters = defaultdict(int)
        self.timers = {}
        self.lock = threading.Lock()
    
    def increment(self, metric_name: str, value: int = 1):
        """Increment a counter metric
        
        Args:
            metric_name: Name of the metric
            value: Value to increment by
        """
        with self.lock:
            self.counters[metric_name] += value
    
    def record(self, metric_name: str, value: float, timestamp: Optional[float] = None):
        """Record a metric value
        
        Args:
            metric_name: Name of the metric
            value: Value to record
            timestamp: Timestamp (uses current time if None)
        """
        if timestamp is None:
            timestamp = time.time()
        
        with self.lock:
            self.metrics[metric_name].append((timestamp, value))
    
    def start_timer(self, timer_name: str):
        """Start a timer
        
        Args:
            timer_name: Name of the timer
        """
        with self.lock:
            self.timers[timer_name] = time.time()
    
    def stop_timer(self, timer_name: str) -> float:
        """Stop a timer and record the elapsed time
        
        Args:
            timer_name: Name of the timer
            
        Returns:
            Elapsed time in seconds
        """
        with self.lock:
            if timer_name in self.timers:
                elapsed = time.time() - self.timers[timer_name]
                del self.timers[timer_name]
                self.record(f"{timer_name}_duration", elapsed)
                return elapsed
            return 0.0
    
    def get_counter(self, metric_name: str) -> int:
        """Get counter value
        
        Args:
            metric_name: Name of the counter
            
        Returns:
            Counter value
        """
        with self.lock:
            return self.counters.get(metric_name, 0)
    
    def get_latest(self, metric_name: str) -> Optional[float]:
        """Get the latest value for a metric
        
        Args:
            metric_name: Name of the metric
            
        Returns:
            Latest value or None if no values recorded
        """
        with self.lock:
            values = self.metrics.get(metric_name)
            if values:
                return values[-1][1]
            return None
    
    def get_average(self, metric_name: str, window_size: Optional[int] = None) -> Optional[float]:
        """Get average value for a metric
        
        Args:
            metric_name: Name of the metric
            window_size: Number of recent values to average (all if None)
            
        Returns:
            Average value or None if no values recorded
        """
        with self.lock:
            values = self.metrics.get(metric_name)
            if not values:
                return None
            
            recent_values = list(values)[-window_size:] if window_size else list(values)
            if recent_values:
                return sum(value for _, value in recent_values) / len(recent_values)
            return None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all metrics
        
        Returns:
            Dictionary containing metrics summary
        """
        with self.lock:
            summary = {
                'counters': dict(self.counters),
                'metrics': {},
                'active_timers': list(self.timers.keys())
            }
            
            for metric_name, values in self.metrics.items():
                if values:
                    latest = values[-1][1]
                    all_values = [value for _, value in values]
                    summary['metrics'][metric_name] = {
                        'latest': latest,
                        'count': len(all_values),
                        'average': sum(all_values) / len(all_values),
                        'min': min(all_values),
                        'max': max(all_values)
                    }
            
            return summary
    
    def reset(self):
        """Reset all metrics"""
        with self.lock:
            self.metrics.clear()
            self.counters.clear()
            self.timers.clear()


# Global metrics collector instance
metrics = MetricsCollector()
