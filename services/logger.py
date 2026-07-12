import json
import logging
import sys
from datetime import datetime, timezone

class StructuredFormatter(logging.Formatter):
    def __init__(self, service: str):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": self.service,
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }

        # Ajouter les champs extra si présents
        extra_fields = ["scan_id", "host", "port", "event", "provider", "severity"]
        for field in extra_fields:
            if hasattr(record, field):
                log_entry[field] = getattr(record, field)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)

def get_logger(service: str) -> logging.Logger:
    logger = logging.getLogger(service)
    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter(service))

    if not logger.handlers:
        logger.addHandler(handler)

    return logger
