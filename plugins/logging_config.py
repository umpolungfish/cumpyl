import logging
import json
import os
import threading
from typing import Any

class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
            "filename": record.filename,
            "lineno": record.lineno,
            "process_id": os.getpid(),
            "thread_id": threading.get_ident(),
            "request_id": getattr(record, "request_id", None)  # Optional for request tracking
        }
        return json.dumps({k: v for k, v in log_entry.items() if v is not None})

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

# Apply in each module
if __name__ == "__main__":
    setup_logging()