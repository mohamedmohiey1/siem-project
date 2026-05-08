from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ------------------- User & Authentication -------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='manager')  # admin, manager
    accepted_policies = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# ------------------- SIEM Core -------------------
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    src_ip = db.Column(db.String(45))
    username = db.Column(db.String(100))
    event_type = db.Column(db.String(50))
    status = db.Column(db.String(20))
    details = db.Column(db.Text)
    request_path = db.Column(db.String(200))
    method = db.Column(db.String(10))
    user_agent = db.Column(db.String(200))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    severity = db.Column(db.String(20))
    rule_name = db.Column(db.String(100))
    description = db.Column(db.Text)
    src_ip = db.Column(db.String(45))
    log_ids = db.Column(db.String(200))
    risk_id = db.Column(db.Integer, db.ForeignKey('risk.id'), nullable=True)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True)
    hostname = db.Column(db.String(100))
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ------------------- Network -------------------
class NetworkConnection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    packets_count = db.Column(db.Integer)
    bytes_total = db.Column(db.Integer)
    is_active = db.Column(db.Boolean, default=False)
    agent_id = db.Column(db.String(50))

class NetworkAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    severity = db.Column(db.String(20))
    alert_type = db.Column(db.String(50))
    src_ip = db.Column(db.String(45))
    description = db.Column(db.Text)
    details = db.Column(db.JSON)

# ------------------- GRC Modules -------------------
class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    likelihood = db.Column(db.Integer)   # 1-5
    impact = db.Column(db.Integer)       # 1-5
    risk_score = db.Column(db.Integer)
    risk_response = db.Column(db.String(50))
    owner = db.Column(db.String(100))
    status = db.Column(db.String(50), default='Open')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=lambda: datetime.now(timezone.utc))

# ------------------- Policy Read Tracking (must come before Policy) -------------------
class PolicyRead(db.Model):
    """Tracks which user has read which policy and when"""
    __tablename__ = 'policy_read'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    policy_id = db.Column(db.Integer, db.ForeignKey('policy.id'), nullable=False)
    read_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = db.relationship('User', backref=db.backref('policy_reads', lazy='dynamic'))
    policy = db.relationship('Policy', backref=db.backref('reads', lazy='dynamic'))

# ------------------- Policy (complete) -------------------
class Policy(db.Model):
    __tablename__ = 'policy'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    policy_type = db.Column(db.String(100))
    version = db.Column(db.String(20))
    summary = db.Column(db.Text)
    full_content = db.Column(db.Text)
    approved_by = db.Column(db.String(100))
    status = db.Column(db.String(50), default='Active')
    last_reviewed = db.Column(db.Date)
    next_review = db.Column(db.Date)
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Who created/updated the policy
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    last_updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    created_by = db.relationship('User', foreign_keys=[created_by_id], backref='created_policies')
    last_updated_by = db.relationship('User', foreign_keys=[last_updated_by_id], backref='updated_policies')
    
    def mark_as_read_by(self, user):
        """Marks this policy as read by a specific user"""
        existing = PolicyRead.query.filter_by(user_id=user.id, policy_id=self.id).first()
        if not existing:
            read_record = PolicyRead(user_id=user.id, policy_id=self.id)
            db.session.add(read_record)
            db.session.commit()
    
    def is_read_by(self, user):
        """Checks if a user has read this policy"""
        return PolicyRead.query.filter_by(user_id=user.id, policy_id=self.id).first() is not None

# ------------------- Compliance, Incidents, BCP, Analysis Requests -------------------
class ComplianceRequirement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    standard = db.Column(db.String(50))   # ISO27001, PCI-DSS, etc.
    req_id = db.Column(db.String(50))
    description = db.Column(db.Text)
    current_status = db.Column(db.String(20))  # Compliant, Partial, Non-Compliant
    evidence = db.Column(db.Text)
    remediation_plan = db.Column(db.Text)
    target_completion = db.Column(db.Date)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    detection_time = db.Column(db.DateTime)
    containment_time = db.Column(db.DateTime)
    resolution_time = db.Column(db.DateTime)
    assignee = db.Column(db.String(100))
    status = db.Column(db.String(50), default='Open')

class CriticalSystem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    rto = db.Column(db.Integer)   # Recovery Time Objective (minutes)
    rpo = db.Column(db.Integer)   # Recovery Point Objective (minutes)
    backup_frequency = db.Column(db.String(50))
    owner = db.Column(db.String(100))

class AnalysisRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    manager_username = db.Column(db.String(80))
    request_message = db.Column(db.Text)
    original_filename = db.Column(db.String(200))
    stored_filename = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # pending, analyzing, completed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    report_generated_at = db.Column(db.DateTime)
    report_data = db.Column(db.JSON)
    risk_score = db.Column(db.Integer)
    risk_id = db.Column(db.Integer, db.ForeignKey('risk.id'))
    report_summary = db.Column(db.String(500))
    is_read = db.Column(db.Boolean, default=False)

class PolicyAcceptance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    policy_id = db.Column(db.Integer, db.ForeignKey('policy.id'))
    accepted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))