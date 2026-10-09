import json
import uvicorn
import sys
import os
import threading
import logging
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from api.main import app
from config import settings
from feeds.scheduler import FeedScheduler


class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "service": "threat-feed",
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


logger = logging.getLogger(__name__)


def _run_scheduler():
    scheduler = FeedScheduler()
    import time
    while True:
        try:
            count = scheduler.poll_all()
            logger.info("Scheduler polled %d IOCs", count)
        except Exception as e:
            logger.error("Scheduler error: %s", e, exc_info=True)
        time.sleep(settings.POLL_INTERVAL_MINUTES * 60)


if __name__ == "__main__":
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO), handlers=[handler])
    logger = logging.getLogger("threat-feed")
    logger.info("Starting Threat Feed Service", extra={"correlation_id": None})
    t = threading.Thread(target=_run_scheduler, daemon=True)
    t.start()
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT, log_config=None)
