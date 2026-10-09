import json
import logging
import sys
import asyncio
import uvicorn
import os
import signal
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from api.main import app
from config import settings


logger = logging.getLogger("log-ingestion")


class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "service": "log-ingestion",
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "correlation_id": getattr(record, "correlation_id", None),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }
        return json.dumps(log_entry, default=str)


def handle_sigterm(signum, frame):
    logger.info("Received SIGTERM/SIGINT, shutting down gracefully...")
    sys.exit(0)


if __name__ == "__main__":
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO), handlers=[handler])
    logger = logging.getLogger("log-ingestion")

    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    logger.info("Starting Log Ingestion Service", extra={"correlation_id": None})
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT, log_config=None)
