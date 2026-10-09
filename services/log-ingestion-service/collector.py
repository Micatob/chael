import json
import logging
import os
import sys
import time
from datetime import datetime

logger = logging.getLogger("windows-collector")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "service": "windows-collector", "message": "%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S"
))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

try:
    import win32evtlog
    import win32evtlogutil
    import requests
except ImportError as e:
    logger.error("Missing dependency: %s. Install with: pip install pywin32 requests", e)
    sys.exit(1)

API_URL = os.getenv("CHAEL_SIEM_URL", "http://127.0.0.1:8000") + "/api/logs/raw/windows"

def collect_events():
    logger.info("Starting Chael SIEM Windows Event Collector, targeting: %s", API_URL)

    server = 'localhost'
    logtype = 'System'

    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
    logger.info("Connected to %s log. Total records: %d", logtype, total_records)

    last_record_number = win32evtlog.GetOldestEventLogRecord(hand) + total_records - 1

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            time.sleep(2)
            continue

        for event in events:
            if event.RecordNumber <= last_record_number:
                continue

            last_record_number = max(last_record_number, event.RecordNumber)

            payload = {
                "event_id": event.EventID & 0xFFFF,
                "source": event.SourceName,
                "timestamp": event.TimeGenerated.isoformat(),
                "event_type": event.EventType,
                "category": event.EventCategory,
                "record_number": event.RecordNumber,
                "computer_name": event.ComputerName,
                "message": str(event.StringInserts) if event.StringInserts else "",
                "raw_data": str(event.RawData) if hasattr(event, 'RawData') else None
            }

            try:
                response = requests.post(API_URL, json=payload)
                if response.status_code == 202:
                    logger.info("Pushed Event %d from %s", payload['event_id'], payload['source'])
                else:
                    logger.warning("Error pushing event: %d - %s", response.status_code, response.text)
            except Exception as e:
                logger.error("Connection error: %s", e)

        time.sleep(1)

if __name__ == "__main__":
    try:
        collect_events()
    except KeyboardInterrupt:
        logger.info("Stopping collector...")
