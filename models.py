from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=True)
    details = db.Column(db.Text, nullable=True)
    request_path = db.Column(db.String(200), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20), nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    src_ip = db.Column(db.String(45), nullable=True)
    log_ids = db.Column(db.String(200), nullable=True)
    is_resolved = db.Column(db.Boolean, default=False)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    hostname = db.Column(db.String(100), nullable=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    os_info = db.Column(db.String(100), nullable=True)

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_ip = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    command = db.Column(db.String(200), nullable=True)
    details = db.Column(db.Text, nullable=True)

class NetworkConnection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), nullable=False)
    packets_count = db.Column(db.Integer, default=0)
    bytes_total = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    agent_id = db.Column(db.String(50), default='default')

class NetworkAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    src_ip = db.Column(db.String(45), nullable=True)
    dst_ip = db.Column(db.String(45), nullable=True)
    description = db.Column(db.Text, nullable=False)
    details = db.Column(db.JSON, nullable=True)
    is_resolved = db.Column(db.Boolean, default=False)

class AnalysisRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    manager_username = db.Column(db.String(80), nullable=False)
    request_message = db.Column(db.Text, nullable=True)
    original_filename = db.Column(db.String(200), nullable=False)   # original name
    stored_filename = db.Column(db.String(200), nullable=False)     # unique name in uploads
    status = db.Column(db.String(20), default='pending')           # pending, analyzing, completed
    report_summary = db.Column(db.Text, nullable=True)             # short summary for listing
    report_data = db.Column(db.JSON, nullable=True)                # full analysis (stats, alerts, recommendations)
    report_generated_at = db.Column(db.DateTime, nullable=True)
    is_read = db.Column(db.Boolean, default=False)                 # for manager notification

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='manager')  # 'admin' or 'manager'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)