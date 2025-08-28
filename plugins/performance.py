"""Performance monitoring utilities."""
import time
import logging
from functools import wraps
from typing import Dict, Any, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    execution_time: float
    memory_usage: float
    success: bool
    error: str = None

def monitor_performance(func: Callable) -> Callable:
    """Decorator to monitor function performance."""
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        start_memory = _get_memory_usage()
        
        try:
            result = func(*args, **kwargs)
            end_time = time.time()
            end_memory = _get_memory_usage()
            
            metrics = PerformanceMetrics(
                execution_time=end_time - start_time,
                memory_usage=end_memory - start_memory,
                success=True
            )
            
            logger.info(f"Performance metrics for {func.__name__}: {metrics}")
            return result, metrics
            
        except Exception as e:
            end_time = time.time()
            metrics = PerformanceMetrics(
                execution_time=end_time - start_time,
                memory_usage=0,
                success=False,
                error=str(e)
            )
            logger.error(f"Performance metrics for {func.__name__}: {metrics}")
            raise
    
    return wrapper

def _get_memory_usage() -> float:
    """Get current memory usage in MB."""
    try:
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    except ImportError:
        return 0