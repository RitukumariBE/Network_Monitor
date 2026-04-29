from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Reference to app's db (will be set by app.py)
db =SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    email = db.Column(db.String(120), nullable=True)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), unique=True, nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    current_status = db.Column(db.String(10), default='UNKNOWN')
    last_checked = db.Column(db.DateTime)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.Index('ix_log_device_timestamp', 'device_id', 'timestamp'),
        db.Index('ix_log_timestamp', 'timestamp'),
    )

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    __table_args__ = (
        db.Index('ix_alert_device_timestamp', 'device_id', 'timestamp'),
        db.Index('ix_alert_timestamp', 'timestamp'),
    )

class EmailConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_email = db.Column(db.String(120), nullable=False)
    sender_password = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


class DeviceAlertCycle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False, unique=True)
    last_status = db.Column(db.String(10), nullable=True)  # Track last status sent in email
    cycle_count = db.Column(db.Integer, default=0)  # Track monitoring cycles to skip first cycle

# ── Add this class to your models.py ──────────────────────────────────────────
# This stores custom device types created by admins.
# Built-in types (cctv, switch, router, etc.) are defined in app.py as BUILTIN_TYPES
# and are NOT stored in this table.

class DeviceType(db.Model):
    __tablename__ = 'device_type'

    id    = db.Column(db.Integer, primary_key=True)
    slug  = db.Column(db.String(60), unique=True, nullable=False, index=True)
    label = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f'<DeviceType {self.slug}>'
