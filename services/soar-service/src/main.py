import json
import logging
import sys
import uvicorn
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from api.main import app
from config import settings


class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "service": "soar-service",
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


if __name__ == "__main__":
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO), handlers=[handler])
    logger = logging.getLogger("soar-service")
    logger.info("Starting SOAR Service", extra={"correlation_id": None})
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT, log_config=None)
