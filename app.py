from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from models import db, User, Device, Log, Alert, EmailConfig, DeviceAlertCycle
import csv
import os
import threading                          # FIX: added for background monitor run
from sqlalchemy import func, case, text
from datetime import datetime, timedelta
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


@app.errorhandler(KeyError)
def handle_key_error(error):
    missing_key = error.args[0] if error.args else 'unknown'
    flash(f"❌ Invalid request format. Missing field: {missing_key}")
    next_route = 'index' if 'user_id' in session else 'login'
    return redirect(url_for(next_route))


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return error
    flash('❌ Unexpected error while processing request. Please try again.')
    next_route = 'index' if 'user_id' in session else 'login'
    return redirect(url_for(next_route))


def scheduled_monitor():
    print("⏰ Scheduler triggered - running monitor...")
    with app.app_context():
        from monitor import run_monitoring
        run_monitoring()
    print("✅ Monitor run complete!")


scheduler = BackgroundScheduler()
scheduler.add_job(
    func=scheduled_monitor,
    trigger='interval',
    minutes=10,
    max_instances=1,
    coalesce=True,
    misfire_grace_time=300
)
scheduler.start()
print("📅 Scheduler started - monitor will run every 10 minutes")


# FIX: track if a manual monitor run is already in progress
_monitor_running = False

def _run_monitor_background():
    """Run monitoring in a background thread so the web request returns instantly."""
    global _monitor_running
    try:
        with app.app_context():
            from monitor import run_monitoring
            run_monitoring()
    except Exception as e:
        print(f"❌ Background monitor error: {e}")
    finally:
        _monitor_running = False
        print("✅ Background monitor run complete!")


def build_dashboard_metrics():
    all_devices = Device.query.all()
    total = len(all_devices)
    up_count = sum(1 for d in all_devices if d.current_status == 'UP')
    down_count = sum(1 for d in all_devices if d.current_status == 'DOWN')
    unknown_count = sum(1 for d in all_devices if d.current_status == 'UNKNOWN')

    type_rows = (
        db.session.query(Device.device_type, func.count(Device.id))
        .group_by(Device.device_type)
        .all()
    )
    type_counts = {device_type: count for device_type, count in type_rows if device_type}

    now = datetime.utcnow().replace(second=0, microsecond=0)
    slot_datetimes = [now - timedelta(minutes=offset) for offset in range(11, -1, -1)]
    slot_labels = [slot.strftime('%Y-%m-%d %H:%M') for slot in slot_datetimes]
    window_start = slot_datetimes[0]

    trend_rows = (
        db.session.query(
            func.strftime('%Y-%m-%d %H:%M', Log.timestamp).label('slot'),
            func.sum(case((Log.status == 'UP', 1), else_=0)).label('up'),
            func.sum(case((Log.status == 'DOWN', 1), else_=0)).label('down'),
            func.sum(case((Log.status == 'UNKNOWN', 1), else_=0)).label('unknown')
        )
        .filter(Log.timestamp >= window_start)
        .group_by('slot')
        .all()
    )

    trend_by_slot = {
        row.slot: {
            "up": int(row.up or 0),
            "down": int(row.down or 0),
            "unknown": int(row.unknown or 0)
        }
        for row in trend_rows
    }

    trend = {
        "labels": slot_labels,
        "up": [trend_by_slot.get(slot, {}).get("up", 0) for slot in slot_labels],
        "down": [trend_by_slot.get(slot, {}).get("down", 0) for slot in slot_labels],
        "unknown": [trend_by_slot.get(slot, {}).get("unknown", 0) for slot in slot_labels]
    }
    trend["up"][-1] = up_count
    trend["down"][-1] = down_count
    trend["unknown"][-1] = unknown_count

    update_rows = (
        db.session.query(
            func.strftime('%Y-%m-%d %H:%M', Log.timestamp).label('slot'),
            func.count(Log.id).label('checks')
        )
        .filter(Log.timestamp >= window_start)
        .group_by('slot')
        .all()
    )

    alert_rows = (
        db.session.query(
            func.strftime('%Y-%m-%d %H:%M', Alert.timestamp).label('slot'),
            func.count(Alert.id).label('changes')
        )
        .filter(Alert.timestamp >= window_start)
        .group_by('slot')
        .all()
    )

    checks_by_slot = {row.slot: int(row.checks or 0) for row in update_rows}
    changes_by_slot = {row.slot: int(row.changes or 0) for row in alert_rows}

    updates = {
        "labels": slot_labels,
        "checks": [checks_by_slot.get(slot, 0) for slot in slot_labels],
        "changes": [changes_by_slot.get(slot, 0) for slot in slot_labels]
    }

    return {
        "counts": {
            "total": total,
            "up": up_count,
            "down": down_count,
            "unknown": unknown_count
        },
        "type_counts": type_counts,
        "trend": trend,
        "updates": updates
    }


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    per_page = 20
    search_query = request.args.get('search', '').strip()
    type_filter = request.args.get('type', '').strip().lower()
    status_filter = request.args.get('status', '').strip().upper()

    all_devices = Device.query.all()
    up_count = sum(1 for d in all_devices if d.current_status == 'UP')
    down_count = sum(1 for d in all_devices if d.current_status == 'DOWN')
    normalized_status = {'ONLINE': 'UP', 'OFFLINE': 'DOWN'}.get(status_filter, status_filter)

    filtered_devices = all_devices
    if search_query:
        s = search_query.lower()
        filtered_devices = [
            d for d in filtered_devices
            if s in (d.ip or '').lower()
            or s in (d.device_type or '').lower()
            or s in (d.location or '').lower()
        ]
    if type_filter:
        filtered_devices = [d for d in filtered_devices if (d.device_type or '').lower() == type_filter]
    if normalized_status in {'UP', 'DOWN', 'UNKNOWN'}:
        filtered_devices = [d for d in filtered_devices if d.current_status == normalized_status]

    total = len(filtered_devices)
    start = (page - 1) * per_page
    end = start + per_page
    devices_page = filtered_devices[start:end]
    total_pages = (total + per_page - 1) // per_page

    dashboard_metrics_data = build_dashboard_metrics()

    return render_template('dashboard.html',
                           devices=devices_page,
                           all_devices=all_devices,
                           up_count=up_count,
                           down_count=down_count,
                           role=session.get('role'),
                           page=page,
                           total_pages=total_pages,
                           total=total,
                           search_query=search_query,
                           type_filter=type_filter,
                           status_filter=normalized_status,
                           dashboard_metrics_data=dashboard_metrics_data)


@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash('Access denied: admin only.')
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('index'))


@app.route('/user')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('index'))


@app.route('/dashboard_metrics')
def dashboard_metrics():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(build_dashboard_metrics())


@app.route('/monitor')
def monitor():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    global _monitor_running

    # FIX: if already running, don't launch another thread
    if _monitor_running:
        flash('⏳ Monitor is already running in the background...')
        return redirect(url_for('index'))

    # FIX: launch in background thread → page returns immediately
    _monitor_running = True
    print("🔍 Manual monitor triggered from dashboard (background thread)...")
    t = threading.Thread(target=_run_monitor_background, daemon=True)
    t.start()

    flash('✅ Monitor started! Results will update automatically in ~30 seconds.')
    return redirect(url_for('index'))


@app.route('/monitor_status')
def monitor_status():
    """Optional: lets the frontend poll if a monitor run is in progress."""
    return jsonify({"running": _monitor_running})


@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    file = request.files.get('csv_file')
    if not file or file.filename == '':
        flash('❌ No file selected!')
        return redirect(url_for('index'))

    if not file.filename.endswith('.csv'):
        flash('❌ Please upload a CSV file only!')
        return redirect(url_for('index'))

    added = 0
    skipped = 0
    errors = 0

    try:
        stream = file.stream.read().decode('utf-8-sig').splitlines()

        if not stream:
            flash('❌ CSV file is empty!')
            return redirect(url_for('index'))

        reader = csv.DictReader(stream)

        if not reader.fieldnames:
            flash('❌ CSV file has no headers!')
            return redirect(url_for('index'))

        reader.fieldnames = [h.strip().lower().replace(' ', '_') for h in reader.fieldnames]

        if 'ip' not in reader.fieldnames:
            flash('❌ CSV must have an "ip" column! Your columns: ' + ', '.join(reader.fieldnames))
            return redirect(url_for('index'))

        allowed_types = ['cctv', 'switch', 'router', 'access_point']

        for row in reader:
            try:
                ip = row.get('ip', '').strip()
                device_type = row.get('device_type', '').strip().lower().replace(' ', '_')
                location = row.get('location', 'Unknown').strip()

                if not ip:
                    skipped += 1
                    continue

                parts = ip.split('.')
                if len(parts) != 4:
                    print(f"⚠️ Skipping invalid IP: {ip}")
                    errors += 1
                    continue

                if device_type not in allowed_types:
                    device_type = 'cctv'

                if not location:
                    location = 'Unknown'

                existing = Device.query.filter_by(ip=ip).first()
                if existing:
                    skipped += 1
                else:
                    device = Device(ip=ip, device_type=device_type, location=location)
                    db.session.add(device)
                    added += 1

            except Exception as row_error:
                print(f"⚠️ Skipping bad row: {row_error}")
                errors += 1
                continue

        db.session.commit()
        flash(f'✅ CSV uploaded! Added: {added} | Skipped: {skipped} | Errors: {errors}')

    except UnicodeDecodeError:
        flash('❌ File encoding error - please save your CSV as UTF-8!')
    except Exception as e:
        flash(f'❌ Upload failed: {str(e)}')

    return redirect(url_for('index'))


@app.route('/test_ping')
def test_ping():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    from ping_engine import ping_device
    result = ping_device('8.8.8.8')
    flash(f'🧪 Test ping to 8.8.8.8 → {result}')
    return redirect(url_for('index'))


@app.route('/users')
def users():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))
    all_users = User.query.all()
    return render_template('users.html', users=all_users, role=session.get('role'))


@app.route('/add_user', methods=['POST'])
def add_user():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    email = (request.form.get('email') or '').strip()
    role = (request.form.get('role') or '').strip()

    existing = User.query.filter_by(username=username).first()
    if existing:
        flash(f'❌ User {username} already exists!')
    else:
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            email=email,
            role=role
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f'✅ User {username} added successfully!')

    return redirect(url_for('users'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    user = User.query.get(user_id)
    if not user:
        flash('❌ User not found!')
        return redirect(url_for('users'))

    if user.username == 'admin':
        flash('❌ Cannot delete admin!')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'✅ User {user.username} deleted!')

    return redirect(url_for('users'))


@app.route('/email_config', methods=['GET', 'POST'])
def email_config():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    config = EmailConfig.query.first()

    if request.method == 'POST':
        sender_email = (request.form.get('sender_email') or '').strip()
        sender_password = request.form.get('sender_password') or ''

        if config:
            config.sender_email = sender_email
            config.sender_password = sender_password
            config.is_active = True
        else:
            config = EmailConfig(
                sender_email=sender_email,
                sender_password=sender_password,
                is_active=True
            )
            db.session.add(config)

        db.session.commit()
        flash('✅ Email settings saved!')
        return redirect(url_for('email_config'))

    return render_template('email_config.html', config=config, role=session.get('role'))


@app.route('/delete_device/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    device = Device.query.get(device_id)
    if not device:
        flash('❌ Device not found!')
        return redirect(url_for('index'))

    try:
        Log.query.filter_by(device_id=device.id).delete(synchronize_session=False)
        Alert.query.filter_by(device_id=device.id).delete(synchronize_session=False)
        DeviceAlertCycle.query.filter_by(device_id=device.id).delete(synchronize_session=False)
        db.session.delete(device)
        db.session.commit()
        flash(f'✅ Device {device.ip} and related history deleted!')
    except Exception:
        db.session.rollback()
        flash('❌ Failed to delete device from database. Please try again.')

    return redirect(url_for('index'))


@app.route('/add_device', methods=['POST'])
def add_device():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    ip = (request.form.get('ip') or '').strip()
    device_type = (request.form.get('device_type') or '').strip()
    location = (request.form.get('location') or '').strip()

    existing = Device.query.filter_by(ip=ip).first()
    if existing:
        flash(f'❌ Device {ip} already exists!')
    else:
        device = Device(ip=ip, device_type=device_type, location=location)
        db.session.add(device)
        db.session.commit()
        flash(f'✅ Device {ip} added!')

    return redirect(url_for('index'))


@app.route('/edit_admin', methods=['GET', 'POST'])
def edit_admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admins only!')
        return redirect(url_for('index'))

    admin = User.query.filter_by(username='admin').first()

    if request.method == 'POST':
        new_email = (request.form.get('email') or '').strip()
        new_password = (request.form.get('password') or '').strip()

        admin.email = new_email
        if new_password:
            admin.password = generate_password_hash(new_password)

        db.session.commit()
        flash('✅ Admin profile updated!')
        return redirect(url_for('edit_admin'))

    return render_template('edit_admin.html', admin=admin, role=session.get('role'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username') or ''
        password = request.form.get('password') or ''

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Invalid credentials!')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Enable WAL mode — prevents "database is locked" when background
        # thread writes while web requests are reading simultaneously
        db.session.execute(text("PRAGMA journal_mode=WAL"))
        db.session.execute(text("PRAGMA synchronous=NORMAL"))
        db.session.commit()
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_log_device_timestamp ON log (device_id, timestamp)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_log_timestamp ON log (timestamp)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alert_device_timestamp ON alert (device_id, timestamp)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alert_timestamp ON alert (timestamp)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_device_alert_cycle_device_id ON device_alert_cycle (device_id)"
        ))
        db.session.commit()

        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin CREATED: admin/admin123")
        else:
            print("✅ Admin exists")

    print("🚀 Ready!")
    app.run(debug=False, use_reloader=False, host="0.0.0.0", port=5000)