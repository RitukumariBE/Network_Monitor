from app import app
from models import db, Device, Log, Alert, User, EmailConfig, DeviceAlertCycle
from ping_engine import ping_device
from datetime import datetime, timedelta
from email_alerts import send_alert_emails
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

MONITOR_RUN_COUNT = 0

def run_monitoring():
    global MONITOR_RUN_COUNT
    MONITOR_RUN_COUNT += 1

    with app.app_context():
        devices = Device.query.all()

        if not devices:
            print("⚠️  No devices found in database")
            return

        print(f"\n🔍 Monitoring {len(devices)} devices...\n")

        email_config = EmailConfig.query.filter_by(is_active=True).first()
        recipient_emails = [u.email for u in User.query.all() if u.email]

        print(f"📧 Email config: {'Found - ' + email_config.sender_email if email_config else 'NOT FOUND'}")
        print(f"📧 Recipients: {recipient_emails}")

        up_count    = 0
        down_count  = 0
        unknown_count = 0
        alert_count = 0

        active_devices = [
            d for d in devices
            if not (d.location and d.location.startswith('[INACTIVE]'))
        ]

        # ── Ping with 100 parallel workers (exactly as requested) ────────────────
        max_workers = 100
        print(f"⚙️  Parallel ping workers: {max_workers}")

        # Ping all active devices concurrently
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
                        print(f"  ❌ Ping worker failed for {device.ip}: {exc}")
                        ping_results[device.id] = ("UNKNOWN", None)

        # pending_emails is a plain list; emails are sent SEQUENTIALLY afterwards
        pending_emails = []
        cycle_rows = {row.device_id: row for row in DeviceAlertCycle.query.all()} if active_devices else {}

        for device in active_devices:

            old_status = device.current_status
            new_status, response_time = ping_results.get(device.id, ("UNKNOWN", None))

            device.current_status = new_status
            device.last_checked   = datetime.utcnow()

            log = Log(device_id=device.id, status=new_status)
            db.session.add(log)

            if new_status == "UP":
                up_count += 1
            elif new_status == "DOWN":
                down_count += 1
            else:
                unknown_count += 1

            # Log status changes to Alert table for dashboard history
            if old_status != new_status:
                message = f"⚠️  {device.ip} changed from {old_status} → {new_status}"
                alert   = Alert(device_id=device.id, message=message)
                db.session.add(alert)
                alert_count += 1
                print(f"  🚨 ALERT: {message}")
            else:
                symbol = "🟢" if new_status == "UP" else ("🔴" if new_status == "DOWN" else "❓")
                if response_time:
                    print(f"  {symbol} {device.ip} → {new_status} ({response_time}ms) (no change)")
                else:
                    print(f"  {symbol} {device.ip} → {new_status} (no change)")

            # Get or create the cycle row for this device
            cycle_row = cycle_rows.get(device.id)
            if cycle_row is None:
                cycle_row = DeviceAlertCycle(device_id=device.id, last_status=None, cycle_count=0)
                db.session.add(cycle_row)
                cycle_rows[device.id] = cycle_row

            # ── Skip first cycle (cycle_count = 0) ──────────────────────────────
            # On first cycle, just record status and skip email
            if cycle_row.cycle_count == 0:
                print(f"  ℹ️  {device.ip} → first cycle, recording status ({new_status}), skipping email")
                cycle_row.last_status = new_status
                cycle_row.cycle_count += 1
                continue

            # ── Email logic: send ONLY on status transitions from cycle 2 onwards ─
            # Check if status actually changed from last email
            last_status = cycle_row.last_status
            
            if old_status != new_status and last_status != new_status:
                # Status changed AND we haven't already sent email for this new status
                # Transitions: UP→DOWN, DOWN→UP, UP→UNKNOWN, DOWN→UNKNOWN, UNKNOWN→UP, UNKNOWN→DOWN, UNKNOWN→UNKNOWN is OK too
                
                if email_config and recipient_emails:
                    print(f"  📬 Queuing email alert for {device.ip}: {last_status} → {new_status}...")
                    pending_emails.append({
                        "device_ip":        device.ip,
                        "old_status":       old_status,
                        "new_status":       new_status,
                        "recipient_emails": recipient_emails,
                    })
                    cycle_row.last_status = new_status  # Update after queueing email
                else:
                    print(f"  ⚠️  No email config or no recipients!")
            else:
                # No email: either status didn't change OR we already sent email for this status
                if old_status == new_status:
                    symbol = "🔕"
                    print(f"  {symbol} {device.ip} → still {new_status}, suppressing repeat email")
                else:
                    symbol = "✓"
                    print(f"  {symbol} {device.ip} → {new_status}, no email (already reported)")

            cycle_row.cycle_count += 1

        db.session.commit()

        # ── Send all queued emails over ONE SMTP connection, sequentially ──────
        # No threading here — parallel SMTP was causing connection drops.
        if pending_emails and email_config:
            send_alert_emails(
                sender_email    = email_config.sender_email,
                sender_password = email_config.sender_password,
                pending_emails  = pending_emails,
            )

        # ── Periodic DB cleanup ────────────────────────────────────────────────
        cleanup_interval_runs = max(1, int(os.getenv("DB_CLEANUP_INTERVAL_RUNS", "12")))
        if MONITOR_RUN_COUNT % cleanup_interval_runs == 0:
            log_retention_days   = max(1, int(os.getenv("LOG_RETENTION_DAYS", "14")))
            alert_retention_days = max(1, int(os.getenv("ALERT_RETENTION_DAYS", "30")))
            log_cutoff           = datetime.utcnow() - timedelta(days=log_retention_days)
            alert_cutoff         = datetime.utcnow() - timedelta(days=alert_retention_days)

            deleted_logs         = Log.query.filter(Log.timestamp < log_cutoff).delete(synchronize_session=False)
            deleted_alerts       = Alert.query.filter(Alert.timestamp < alert_cutoff).delete(synchronize_session=False)
            deleted_orphan_cycles = DeviceAlertCycle.query.filter(
                ~DeviceAlertCycle.device_id.in_(db.session.query(Device.id))
            ).delete(synchronize_session=False)
            db.session.commit()
            print(
                f"🧹 Cleanup done: logs={deleted_logs}, alerts={deleted_alerts}, "
                f"orphan_cycles={deleted_orphan_cycles}"
            )

        print(f"\n✅ Monitoring complete!")
        print(f"   🟢 UP: {up_count} | 🔴 DOWN: {down_count} | ❓ UNKNOWN: {unknown_count} | 🚨 Alerts: {alert_count}")


if __name__ == "__main__":
    run_monitoring()
