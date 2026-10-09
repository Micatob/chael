import json
import logging
import sys
import os
import uvicorn
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from api import app
from config import settings

if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    logger = logging.getLogger("sigma-converter")
    logger.info("Starting Sigma Rule Converter Service")
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT, log_config=None)