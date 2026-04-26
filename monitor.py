from app import app
from models import db, Device, Log, Alert, User, EmailConfig, DeviceAlertCycle
from ping_engine import ping_device
from datetime import datetime, timezone, timedelta
from email_alerts import send_alert_emails
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import threading
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),                  # console output
        logging.FileHandler("monitor.log"),        # persistent log file
    ]
)
logger = logging.getLogger(__name__)


MONITOR_RUN_COUNT = 0

_monitor_lock = threading.Lock()


def utcnow():
    return datetime.now(timezone.utc)


def run_monitoring():
    if not _monitor_lock.acquire(blocking=False):
        logger.warning("⚠️  Monitor already running — skipping this trigger.")
        return

    try:
        _run_this_cycle()
    finally:
        _monitor_lock.release()


def _run_this_cycle():
    global MONITOR_RUN_COUNT
    with _run_count_lock:
        MONITOR_RUN_COUNT += 1
        current_run = MONITOR_RUN_COUNT

    with app.app_context():
        devices = Device.query.all()

        if not devices:
            logger.warning("⚠️  No devices found in database.")
            return

        logger.info(f"🔍 Monitoring {len(devices)} devices... (run #{current_run})")

        email_config = EmailConfig.query.filter_by(is_active=True).first()
        recipient_emails = [u.email for u in User.query.all() if u.email]

        logger.info(f"📧 Email config: {'Found - ' + email_config.sender_email if email_config else 'NOT FOUND'}")
        logger.info(f"📧 Recipients: {recipient_emails}")

        up_count      = 0
        down_count    = 0
        unknown_count = 0
        alert_count   = 0

        active_devices = [d for d in devices if getattr(d, 'is_active', True)]

        max_workers = min(100, len(active_devices))  # don't spin up unused threads
        logger.info(f"⚙️  Parallel ping workers: {max_workers}")

        ping_results = {}
        if active_devices:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_device = {
                    executor.submit(ping_device, device.ip): device
                    for device in active_devices
                }
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        ping_results[device.id] = future.result()
                    except Exception as exc:
                        logger.error(f"❌ Ping worker failed for {device.ip}: {exc}")
                        ping_results[device.id] = ("UNKNOWN", None)

        pending_emails = []
        cycle_rows = {
            row.device_id: row
            for row in DeviceAlertCycle.query.all()
        } if active_devices else {}

        for device in active_devices:

            old_status = device.current_status
            new_status, response_time = ping_results.get(device.id, ("UNKNOWN", None))

            device.current_status = new_status
            device.last_checked   = utcnow()          # FIX #1: timezone-aware

            log = Log(device_id=device.id, status=new_status)
            db.session.add(log)

            if new_status == "UP":
                up_count += 1
            elif new_status == "DOWN":
                down_count += 1
            else:
                unknown_count += 1

            if old_status != new_status:
                message = f"⚠️  {device.ip} changed from {old_status} → {new_status}"
                alert   = Alert(device_id=device.id, message=message)
                db.session.add(alert)
                alert_count += 1
                logger.warning(f"🚨 ALERT: {message}")
            else:
                symbol = "🟢" if new_status == "UP" else ("🔴" if new_status == "DOWN" else "❓")
                if response_time is not None:
                    logger.info(f"  {symbol} {device.ip} → {new_status} ({response_time}ms) (no change)")
                else:
                    logger.info(f"  {symbol} {device.ip} → {new_status} (no change)")

            cycle_row = cycle_rows.get(device.id)
            if cycle_row is None:
                cycle_row = DeviceAlertCycle(
                    device_id=device.id,
                    last_status=None,
                    cycle_count=0
                )
                db.session.add(cycle_row)
                cycle_rows[device.id] = cycle_row

            if cycle_row.cycle_count == 0:
                logger.info(f"  ℹ️  {device.ip} → first cycle, recording status ({new_status}), skipping email")
                cycle_row.last_status = new_status
                cycle_row.cycle_count += 1
                continue

            if new_status != cycle_row.last_status:
                if email_config and recipient_emails:
                    logger.info(f"  📬 Queuing email: {device.ip} {cycle_row.last_status} → {new_status}")
                    pending_emails.append({
                        "device_ip":        device.ip,
                        "old_status":       cycle_row.last_status,
                        "new_status":       new_status,
                        "recipient_emails": recipient_emails,
                    })
                    cycle_row.last_status = new_status   # only update after queuing
                else:
                    logger.warning(f"  ⚠️  No email config or no recipients for {device.ip}!")
            else:
                logger.info(f"  🔕 {device.ip} → still {new_status}, suppressing repeat email")

            cycle_row.cycle_count += 1

        db.session.commit()

        if pending_emails and email_config:
            send_alert_emails(
                sender_email    = email_config.sender_email,
                sender_password = email_config.sender_password,
                pending_emails  = pending_emails,
            )

        cleanup_interval_runs = max(1, int(os.getenv("DB_CLEANUP_INTERVAL_RUNS", "12")))
        if current_run % cleanup_interval_runs == 0:
            log_retention_days   = max(1, int(os.getenv("LOG_RETENTION_DAYS", "14")))
            alert_retention_days = max(1, int(os.getenv("ALERT_RETENTION_DAYS", "30")))

            log_cutoff   = utcnow() - timedelta(days=log_retention_days)
            alert_cutoff = utcnow() - timedelta(days=alert_retention_days)

            deleted_logs   = Log.query.filter(Log.timestamp < log_cutoff).delete(synchronize_session=False)
            deleted_alerts = Alert.query.filter(Alert.timestamp < alert_cutoff).delete(synchronize_session=False)

            deleted_orphan_cycles = DeviceAlertCycle.query.filter(
                ~DeviceAlertCycle.device_id.in_(
                    db.session.query(Device.id)
                )
            ).delete(synchronize_session=False)

            db.session.commit()
            logger.info(
                f"🧹 Cleanup done: logs={deleted_logs}, "
                f"alerts={deleted_alerts}, orphan_cycles={deleted_orphan_cycles}"
            )

        logger.info(
            f"\n✅ Monitoring complete! "
            f"🟢 UP: {up_count} | 🔴 DOWN: {down_count} | "
            f"❓ UNKNOWN: {unknown_count} | 🚨 Alerts: {alert_count}"
        )


if __name__ == "__main__":
    run_monitoring()
