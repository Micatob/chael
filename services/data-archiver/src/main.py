import time
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from config import settings
from archiver import DataArchiver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("data-archiver-main")

def _parse_cron(expr: str):
    parts = (expr or "").split()
    if len(parts) != 5:
        return None
    minute, hour, day, month, day_of_week = parts
    return {"minute": minute, "hour": hour, "day": day, "month": month,
            "day_of_week": day_of_week}


def main():
    logger.info("Initializing Data Archiver Service...")
    archiver = DataArchiver()

    # Run once on startup to catch up
    logger.info("Running initial archive cycle on startup...")
    archiver.run_archive_cycle()

    archive_cron = _parse_cron(settings.ARCHIVE_SCHEDULE_CRON)
    if not archive_cron:
        logger.error(f"Invalid CRON expression: {settings.ARCHIVE_SCHEDULE_CRON}. Service exiting.")
        return

    scheduler = BackgroundScheduler()
    scheduler.add_job(archiver.run_archive_cycle, 'cron', **archive_cron)
    logger.info(f"Archive scheduler started with CRON: {settings.ARCHIVE_SCHEDULE_CRON}")

    # SOC digests (daily + weekly) share the same scheduler
    if settings.DIGEST_ENABLED:
        from digest import run_digest

        def _daily():
            try:
                run_digest(archiver.os_client, "daily")
            except Exception as e:
                logger.error("Daily digest failed: %s", e)

        def _weekly():
            try:
                run_digest(archiver.os_client, "weekly")
            except Exception as e:
                logger.error("Weekly digest failed: %s", e)

        daily = _parse_cron(settings.DIGEST_DAILY_CRON)
        weekly = _parse_cron(settings.DIGEST_WEEKLY_CRON)
        if daily:
            scheduler.add_job(_daily, 'cron', **daily)
            logger.info(f"Daily digest scheduled: {settings.DIGEST_DAILY_CRON}")
        if weekly:
            scheduler.add_job(_weekly, 'cron', **weekly)
            logger.info(f"Weekly digest scheduled: {settings.DIGEST_WEEKLY_CRON}")

    scheduler.start()
    logger.info("Scheduler started.")

    try:
        # Keep the main thread alive
        while True:
            time.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logger.info("Scheduler shut down.")

if __name__ == "__main__":
    main()
