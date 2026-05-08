# app.py - SIEM/GRC Enterprise Edition (Final with Mandatory Policy Acceptance)laaaaaaast version
# ============================================================
import os
import re
import uuid
import traceback
import threading
import time
import sqlite3
import subprocess
import platform
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from queue import Queue

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from sqlalchemy import func
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.arch import get_if_list

from models import PolicyRead, db, User, Log, Alert, Device, UserActivity, NetworkConnection, NetworkAlert, AnalysisRequest, Risk, Policy, ComplianceRequirement, Incident, CriticalSystem, PolicyAcceptance

# ============================================================
# 1. Detection Rules
# ============================================================
def apply_detection_rules(log_entry):
    alerts = []
    if log_entry.event_type == 'login' and log_entry.status == 'failed':
        alerts.append(Alert(
            severity='High',
            rule_name='Failed Login Attempt',
            description=f'Failed login attempt from {log_entry.src_ip}',
            src_ip=log_entry.src_ip,
            log_ids=str(log_entry.id)
        ))
    if log_entry.request_path and any(p in log_entry.request_path.lower()
                                      for p in ['/admin', '/phpmyadmin', '/wp-admin', '/config', '/backup']):
        alerts.append(Alert(
            severity='Medium',
            rule_name='Suspicious Web Access',
            description=f'Sensitive path accessed: {log_entry.request_path} from {log_entry.src_ip}',
            src_ip=log_entry.src_ip,
            log_ids=str(log_entry.id)
        ))
    if log_entry.event_type == 'error':
        alerts.append(Alert(
            severity='Low',
            rule_name='Application Error',
            description=f'Error logged: {log_entry.details[:100]}',
            src_ip=log_entry.src_ip,
            log_ids=str(log_entry.id)
        ))
    return alerts

def auto_create_risk_from_alert(alert):
    existing = Risk.query.filter(
        Risk.status == 'Open',
        Risk.title.contains(alert.rule_name),
        Risk.description.contains(alert.src_ip or ''),
        Risk.created_at >= datetime.now(timezone.utc) - timedelta(hours=1)
    ).first()
    if existing:
        alert.risk_id = existing.id
        db.session.commit()
        return existing
    severity_map = {'Critical':5,'High':4,'Medium':3,'Low':2,'Info':1}
    likelihood = severity_map.get(alert.severity,3)
    risk = Risk(
        title=f"[Auto] {alert.rule_name} from {alert.src_ip or 'unknown'}",
        description=f"Auto-created from alert #{alert.id}: {alert.description}",
        category="SIEM Auto",
        likelihood=likelihood,
        impact=likelihood,
        risk_score=likelihood*likelihood,
        risk_response="Review",
        owner="Admin",
        status="Open"
    )
    db.session.add(risk)
    db.session.flush()
    alert.risk_id = risk.id
    db.session.commit()
    return risk

# ============================================================
# 2. Flask Setup
# ============================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///siem.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = './uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================================
# 2b. Policy Acceptance Enforcer (Mandatory for all users)
# ============================================================
@app.before_request
def enforce_policy_acceptance():
    # المسارات المسموح بها دون موافقة
    allowed_endpoints = ['login', 'logout', 'accept_policies', 'static']
    if current_user.is_authenticated and not current_user.accepted_policies:
        if request.endpoint not in allowed_endpoints:
            # حفظ المسار الأصلي لإعادة التوجيه بعد الموافقة
            return redirect(url_for('accept_policies', next=request.url))

# ============================================================
# 3. Globals & Sniffer
# ============================================================
sniffer_active = False
sniffer_thread = None
sniffer_interface = None
temp_connections = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': None, 'src_port': None, 'dst_port': None})
temp_lock = threading.Lock()
agent_active = False
packet_queue = Queue(maxsize=5000)

def get_available_interfaces():
    try:
        return get_if_list()
    except:
        return []

def packet_callback(packet):
    global sniffer_active
    if not sniffer_active:
        return
    try:
        src_ip = "0.0.0.0"
        dst_ip = None
        protocol = "Other"
        src_port = None
        dst_port = None
        size = len(packet)
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
        now = datetime.now(timezone.utc).strftime('%H:%M:%S')
        packet_data = {'timestamp': now, 'src_ip': src_ip, 'protocol': protocol, 'size': size}
        if not packet_queue.full():
            packet_queue.put(packet_data)
        key = (src_ip, dst_ip, src_port or 0, dst_port or 0, protocol)
        with temp_lock:
            conn = temp_connections[key]
            conn['packets'] += 1
            conn['bytes'] += size
            conn['last_seen'] = datetime.now(timezone.utc)
            conn['src_port'] = src_port
            conn['dst_port'] = dst_port
        time.sleep(0)
    except Exception as e:
        print(f"Packet callback error: {e}")

def sniff_loop(interface=None):
    sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda x: not sniffer_active)

def socket_batch_worker():
    batch = []
    while True:
        try:
            while not packet_queue.empty():
                batch.append(packet_queue.get())
            if batch:
                socketio.emit('new_packet_batch', batch)
                batch.clear()
            time.sleep(0.3)
        except Exception as e:
            print(f"Batch worker error: {e}")

# Sniffer routes
@app.route('/network_interfaces')
@login_required
def network_interfaces():
    return jsonify(get_available_interfaces())

@app.route('/start_sniffer', methods=['POST'])
@login_required
def start_sniffer():
    global sniffer_active, sniffer_thread, sniffer_interface
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    if sniffer_active:
        return jsonify({'status': 'Sniffer already running'}), 400
    data = request.get_json() or {}
    sniffer_interface = data.get('interface', None)
    sniffer_active = True
    sniffer_thread = threading.Thread(target=sniff_loop, args=(sniffer_interface,), daemon=True)
    sniffer_thread.start()
    return jsonify({'status': 'Sniffer started', 'interface': sniffer_interface})

@app.route('/stop_sniffer', methods=['POST'])
@login_required
def stop_sniffer():
    global sniffer_active
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    sniffer_active = False
    return jsonify({'status': 'Sniffer stopped'})

@app.route('/sniffer_status')
@login_required
def sniffer_status():
    return jsonify({'active': sniffer_active, 'interface': sniffer_interface})

@app.route('/sniffer')
@login_required
def sniffer_page():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    return render_template('sniffer.html')

# Agent & threat analysis
def agent_save_connections():
    global agent_active, temp_connections
    while agent_active:
        time.sleep(30)
        with app.app_context():
            try:
                with temp_lock:
                    to_save = list(temp_connections.items())
                    temp_connections.clear()
                for (src_ip, dst_ip, src_port, dst_port, protocol), data in to_save:
                    if data['packets'] == 0:
                        continue
                    conn = NetworkConnection(
                        timestamp=data['last_seen'] or datetime.now(timezone.utc),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port or data.get('src_port'),
                        dst_port=dst_port or data.get('dst_port'),
                        protocol=protocol,
                        packets_count=data['packets'],
                        bytes_total=data['bytes'],
                        is_active=False,
                        agent_id='main_agent'
                    )
                    db.session.add(conn)
                db.session.commit()
            except Exception as e:
                print(f"[Agent ERROR] {e}")

def advanced_threat_analysis():
    while True:
        time.sleep(300)
        with app.app_context():
            try:
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                port_scan = defaultdict(set)
                conns = NetworkConnection.query.filter(NetworkConnection.timestamp >= cutoff).all()
                for conn in conns:
                    if conn.dst_port:
                        port_scan[conn.src_ip].add(conn.dst_port)
                for ip, ports in port_scan.items():
                    if len(ports) > 20:
                        existing = NetworkAlert.query.filter(
                            NetworkAlert.alert_type == 'port_scan',
                            NetworkAlert.src_ip == ip,
                            NetworkAlert.timestamp >= datetime.now(timezone.utc) - timedelta(hours=1)
                        ).first()
                        if not existing:
                            alert = NetworkAlert(
                                severity='High',
                                alert_type='port_scan',
                                src_ip=ip,
                                description=f'Port scan detected from {ip} targeting {len(ports)} ports in 5 min',
                                details={'ports': list(ports)[:20]}
                            )
                            db.session.add(alert)
                conn_count = defaultdict(int)
                for conn in conns:
                    conn_count[conn.src_ip] += 1
                for ip, count in conn_count.items():
                    if count > 100:
                        existing = NetworkAlert.query.filter(
                            NetworkAlert.alert_type == 'excessive_connections',
                            NetworkAlert.src_ip == ip,
                            NetworkAlert.timestamp >= datetime.now(timezone.utc) - timedelta(hours=1)
                        ).first()
                        if not existing:
                            alert = NetworkAlert(
                                severity='Medium',
                                alert_type='excessive_connections',
                                src_ip=ip,
                                description=f'Excessive connections ({count}) from {ip} in 5 min'
                            )
                            db.session.add(alert)
                db.session.commit()
            except Exception as e:
                print("Threat analysis error:", e)

def start_agent_thread():
    global agent_active
    agent_active = True
    threading.Thread(target=agent_save_connections, daemon=True).start()
    threading.Thread(target=advanced_threat_analysis, daemon=True).start()

@app.route('/api/agent/connections', methods=['POST'])
def agent_connections():
    data = request.json
    if not data:
        return jsonify({'error': 'No data'}), 400
    agent_id = data.get('agent_id', 'unknown')
    connections_list = data.get('connections', [])
    for conn_data in connections_list:
        conn = NetworkConnection(
            timestamp=datetime.fromisoformat(conn_data['last_seen']) if conn_data.get('last_seen') else datetime.now(timezone.utc),
            src_ip=conn_data['src_ip'],
            dst_ip=conn_data['dst_ip'],
            src_port=conn_data.get('src_port'),
            dst_port=conn_data.get('dst_port'),
            protocol=conn_data['protocol'],
            packets_count=conn_data.get('packets', 0),
            bytes_total=conn_data.get('bytes', 0),
            is_active=False,
            agent_id=agent_id
        )
        db.session.add(conn)
    db.session.commit()
    return jsonify({'status': 'ok', 'received': len(connections_list)}), 200

# ============================================================
# 7. Helper Functions (Log parsing, device update)
# ============================================================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'log', 'txt', 'csv'}

def parse_log_line(line):
    entry = {
        'src_ip': None, 'username': None, 'timestamp': None, 'event_type': 'unknown',
        'status': None, 'details': line.strip(), 'request_path': None, 'method': None, 'user_agent': None
    }
    time_patterns = [
        (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
        (r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        (r'([A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S')
    ]
    for pat, fmt in time_patterns:
        m = re.search(pat, line)
        if m:
            try:
                entry['timestamp'] = datetime.strptime(m.group(1), fmt)
                break
            except:
                pass
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
    if ip_match:
        entry['src_ip'] = ip_match.group()
    user_match = re.search(r'user[= ]([a-zA-Z0-9_]+)', line, re.I) or re.search(r'username[= ]([a-zA-Z0-9_]+)', line, re.I)
    if not user_match:
        user_match = re.search(r'for (invalid user )?([a-zA-Z0-9_]+) from', line, re.I)
        if user_match:
            entry['username'] = user_match.group(2)
    if user_match and not entry['username']:
        entry['username'] = user_match.group(1)
    web_match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^"]+)"', line, re.I)
    if web_match:
        entry['method'] = web_match.group(1).upper()
        entry['request_path'] = web_match.group(2)
        entry['event_type'] = 'web_request'
        status_match = re.search(r'" (\d{3}) ', line)
        if status_match:
            code = int(status_match.group(1))
            if 200 <= code < 300:
                entry['status'] = 'success'
            elif 400 <= code < 500:
                entry['status'] = 'failed'
    if 'Failed password' in line:
        entry['event_type'] = 'login'
        entry['status'] = 'failed'
    elif 'Accepted password' in line:
        entry['event_type'] = 'login'
        entry['status'] = 'success'
    elif 'login' in line.lower():
        entry['event_type'] = 'login'
        if 'success' in line.lower():
            entry['status'] = 'success'
        elif 'fail' in line.lower():
            entry['status'] = 'failed'
    elif 'error' in line.lower():
        entry['event_type'] = 'error'
        entry['status'] = 'error'
    return entry

def update_device(ip, hostname=None):
    if ip == '0.0.0.0' or not ip:
        return
    dev = Device.query.filter_by(ip=ip).first()
    if dev:
        dev.last_seen = datetime.now(timezone.utc)
        if hostname:
            dev.hostname = hostname
    else:
        dev = Device(ip=ip, hostname=hostname or ip)
        db.session.add(dev)
    db.session.commit()

def process_log_line(line, source='upload'):
    parsed = parse_log_line(line)
    if not parsed['src_ip'] or parsed['src_ip'] == '0.0.0.0':
        parsed['src_ip'] = source if source != 'upload' else 'unknown'
    log = Log(
        timestamp=parsed['timestamp'] or datetime.now(timezone.utc),
        src_ip=parsed['src_ip'], username=parsed['username'],
        event_type=parsed['event_type'], status=parsed['status'],
        details=parsed['details'], request_path=parsed['request_path'],
        method=parsed['method'], user_agent=parsed['user_agent']
    )
    db.session.add(log)
    db.session.commit()
    update_device(parsed['src_ip'])
    alerts = apply_detection_rules(log)
    for alert in alerts:
        db.session.add(alert)
        db.session.flush()
        auto_create_risk_from_alert(alert)
    db.session.commit()
    return log

def calculate_mttd():
    total_diff = 0
    count = 0
    alerts = Alert.query.filter(Alert.log_ids.isnot(None)).all()
    for alert in alerts:
        if alert.log_ids:
            first_log_id = alert.log_ids.split(',')[0]
            try:
                log = Log.query.get(int(first_log_id))
                if log and log.timestamp and alert.timestamp:
                    diff = (alert.timestamp - log.timestamp).total_seconds()
                    if diff > 0:
                        total_diff += diff
                        count += 1
            except:
                continue
    return total_diff / count if count > 0 else 0

def analyze_uploaded_file(filepath, request_id):
    total_lines = success_count = failed_count = 0
    login_failed = 0
    top_ips = defaultdict(int)
    event_types = defaultdict(int)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                log = process_log_line(line, source=f'request_{request_id}')
                if log.status == 'success':
                    success_count += 1
                elif log.status == 'failed':
                    failed_count += 1
                if log.event_type == 'login' and log.status == 'failed':
                    login_failed += 1
                if log.src_ip:
                    top_ips[log.src_ip] += 1
                event_types[log.event_type] += 1
    except Exception as e:
        print(f"Error analyzing file: {e}")
        return None
    event_types['login_failed'] = login_failed
    alerts_list = []
    if top_ips:
        recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
        for alert in recent_alerts:
            if alert.src_ip in top_ips:
                alerts_list.append({
                    'severity': alert.severity, 'rule': alert.rule_name,
                    'desc': alert.description, 'ip': alert.src_ip,
                    'time': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                })
    recommendations = []
    if failed_count > success_count and success_count > 0:
        recommendations.append("High failure rate – check login validity or possible attack.")
    if login_failed > 10:
        recommendations.append("Many failed login attempts – enable account lockout or CAPTCHA.")
    high_freq_ips = [ip for ip, cnt in top_ips.items() if cnt > 20]
    if high_freq_ips:
        recommendations.append(f"Frequent IPs: {', '.join(high_freq_ips[:3])}. Investigate and consider blacklisting.")
    if not recommendations:
        recommendations.append("No specific recommendations based on current analysis. Continue periodic monitoring.")
    recommendations.append("Update detection rules regularly.")
    risk_score = 0
    if total_lines > 0:
        fail_ratio = (failed_count / total_lines) * 100
        if fail_ratio > 50:
            risk_score += 40
        elif fail_ratio > 20:
            risk_score += 20
        if login_failed > 10:
            risk_score += 30
        elif login_failed > 5:
            risk_score += 15
        high_freq_count = sum(1 for cnt in top_ips.values() if cnt > 20)
        if high_freq_count > 0:
            risk_score += min(20, high_freq_count * 5)
    risk_score = min(risk_score, 100)
    report_data = {
        'total_lines': total_lines, 'success': success_count, 'failed': failed_count,
        'top_ips': dict(sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
        'event_types': dict(event_types), 'alerts': alerts_list[:20],
        'recommendations': recommendations,
        'risk_score': risk_score
    }
    return report_data

# ============================================================
# 8. Authentication & Basic Routes (with policy enforcement)
# ============================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            # بعد تسجيل الدخول، إذا لم يوافق على السياسات، إعادة توجيه مباشرة
            if not user.accepted_policies:
                return redirect(url_for('accept_policies', next=request.args.get('next') or url_for('dashboard' if user.role == 'admin' else 'report')))
            # إذا وافق من قبل، التوجيه حسب الدور
            if user.role == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('report'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/accept-policies', methods=['GET', 'POST'])
@login_required
def accept_policies():
    active_policies = Policy.query.filter_by(status='Active').all()
    # إذا لم توجد سياسات نشطة، وافق تلقائياً وأعد التوجيه
    if not active_policies:
        current_user.accepted_policies = True
        db.session.commit()
        next_page = request.args.get('next') or (url_for('dashboard') if current_user.role == 'admin' else url_for('report'))
        return redirect(next_page)

    if request.method == 'POST':
        accepted_ids = request.form.getlist('accepted_policies')
        if len(accepted_ids) != len(active_policies):
            flash('يجب الموافقة على جميع السياسات.', 'danger')
            return redirect(url_for('accept_policies', next=request.args.get('next')))
        current_user.accepted_policies = True
        db.session.commit()
        flash('تمت الموافقة على السياسات بنجاح.', 'success')
        next_page = request.args.get('next')
        if not next_page:
            next_page = url_for('dashboard') if current_user.role == 'admin' else url_for('report')
        return redirect(next_page)

    return render_template('accept_policies.html', policies=active_policies)

@app.route('/')
@login_required
def dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    total_logs = Log.query.count()
    total_alerts = Alert.query.count()
    success_logs = Log.query.filter_by(status='success').count()
    failed_logs = Log.query.filter_by(status='failed').count()
    devices_count = Device.query.count()
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    top_attackers = db.session.query(Alert.src_ip, func.count(Alert.id))\
        .filter(Alert.src_ip.isnot(None))\
        .group_by(Alert.src_ip)\
        .order_by(func.count(Alert.id).desc())\
        .limit(5).all()
    admin_requests = AnalysisRequest.query.order_by(AnalysisRequest.created_at.desc()).all() if current_user.role == 'admin' else []
    return render_template('index.html',
                           total_logs=total_logs,
                           total_alerts=total_alerts,
                           success_logs=success_logs,
                           failed_logs=failed_logs,
                           devices_count=devices_count,
                           recent_alerts=recent_alerts,
                           top_attackers=top_attackers,
                           admin_requests=admin_requests)

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    request_sent = False
    if request.method == 'POST':
        analysis_request = request.form.get('analysis_request', '')
        if analysis_request:
            req_filename = f"request_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            req_path = os.path.join(app.config['UPLOAD_FOLDER'], req_filename)
            with open(req_path, 'w', encoding='utf-8') as f:
                f.write(f"From: {current_user.username}\n")
                f.write(f"Message: {analysis_request}\n")
                f.write(f"File: {request.files.get('file').filename if request.files.get('file') else 'None'}\n")
            if request.files.get('file'):
                file = request.files['file']
                if file and allowed_file(file.filename):
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename)))
            request_sent = True
    total_logs = Log.query.count()
    total_alerts = Alert.query.count()
    success_count = Log.query.filter_by(status='success').count()
    failed_count = Log.query.filter_by(status='failed').count()
    top_ips = db.session.query(Log.src_ip, func.count(Log.id))\
        .group_by(Log.src_ip)\
        .order_by(func.count(Log.id).desc())\
        .limit(5).all()
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    report_data = {
        'total_logs': total_logs,
        'total_alerts': total_alerts,
        'success_rate': (success_count / total_logs * 100) if total_logs else 0,
        'failed_count': failed_count,
        'top_ips': top_ips,
        'recent_alerts': recent_alerts
    }
    return render_template('report.html', report=report_data, request_sent=request_sent)

# ============================================================
# 9. Logs, Alerts, Devices, Network Views
# ============================================================
@app.route('/logs')
@login_required
def view_logs():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    src_ip = request.args.get('src_ip', '')
    status = request.args.get('status', '')
    query = Log.query
    if src_ip:
        query = query.filter(Log.src_ip.contains(src_ip))
    if status:
        query = query.filter_by(status=status)
    logs = query.order_by(Log.timestamp.desc()).paginate(page=page, per_page=per_page)
    return render_template('logs.html', logs=logs, src_ip=src_ip, selected_status=status)

@app.route('/alerts')
@login_required
def view_alerts():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    alerts = query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('alerts.html', alerts=alerts, selected_severity=severity)

@app.route('/submit_log', methods=['GET', 'POST'])
@login_required
def submit_log_form():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    if request.method == 'POST':
        data = {
            'src_ip': request.form['src_ip'],
            'username': request.form.get('username'),
            'event_type': request.form['event_type'],
            'status': request.form.get('status'),
            'details': request.form.get('details'),
            'request_path': request.form.get('request_path'),
            'method': request.form.get('method')
        }
        log = Log(**data)
        db.session.add(log)
        db.session.commit()
        update_device(log.src_ip)
        alerts = apply_detection_rules(log)
        for alert in alerts:
            db.session.add(alert)
            db.session.flush()
            auto_create_risk_from_alert(alert)
        db.session.commit()
        return render_template('submit_log.html', success=True, log=data)
    return render_template('submit_log.html')

@app.route('/upload_logs', methods=['GET', 'POST'])
@login_required
def upload_logs():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    stats = None
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(path)
            success_count = failed_count = total_lines = 0
            paths = {}
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_lines += 1
                    log = process_log_line(line, source='upload')
                    if log.status == 'success':
                        success_count += 1
                    elif log.status == 'failed':
                        failed_count += 1
                    if log.request_path:
                        paths[log.request_path] = paths.get(log.request_path, 0) + 1
            alert_count = Alert.query.count()
            stats = {'total_lines': total_lines, 'success': success_count, 'failed': failed_count,
                     'alerts': alert_count, 'filename': filename, 'paths': paths}
    return render_template('upload.html', stats=stats)

@app.route('/devices')
@login_required
def devices():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    all_devices = Device.query.order_by(Device.last_seen.desc()).all()
    dev_list = []
    for dev in all_devices:
        success_cnt = Log.query.filter_by(src_ip=dev.ip, status='success').count()
        failed_cnt = Log.query.filter_by(src_ip=dev.ip, status='failed').count()
        last_log = Log.query.filter_by(src_ip=dev.ip).order_by(Log.timestamp.desc()).first()
        dev_list.append({
            'ip': dev.ip,
            'hostname': dev.hostname,
            'first_seen': dev.first_seen,
            'last_seen': dev.last_seen,
            'success_count': success_cnt,
            'failed_count': failed_cnt,
            'last_activity': last_log.timestamp if last_log else None
        })
    return render_template('devices.html', devices=dev_list)

@app.route('/device/<ip>')
@login_required
def device_details(ip):
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    logs = Log.query.filter_by(src_ip=ip).order_by(Log.timestamp.desc()).limit(200).all()
    alerts = Alert.query.filter_by(src_ip=ip).order_by(Alert.timestamp.desc()).all()
    device = Device.query.filter_by(ip=ip).first()
    return render_template('device_details.html', ip=ip, device=device, logs=logs, alerts=alerts)

@app.route('/network_connections')
@login_required
def network_connections():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    src_ip = request.args.get('src_ip', '')
    dst_ip = request.args.get('dst_ip', '')
    protocol = request.args.get('protocol', '')
    query = NetworkConnection.query
    if src_ip:
        query = query.filter(NetworkConnection.src_ip.contains(src_ip))
    if dst_ip:
        query = query.filter(NetworkConnection.dst_ip.contains(dst_ip))
    if protocol:
        query = query.filter_by(protocol=protocol)
    connections = query.order_by(NetworkConnection.timestamp.desc()).paginate(page=page, per_page=per_page)
    return render_template('network_connections.html', connections=connections,
                           src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)

@app.route('/network_alerts')
@login_required
def network_alerts():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    alerts = NetworkAlert.query.order_by(NetworkAlert.timestamp.desc()).all()
    return render_template('network_alerts.html', alerts=alerts)

def discover_network_devices():
    devices = []
    system = platform.system()
    try:
        if system == 'Windows':
            output = subprocess.check_output(['arp', '-a'], shell=True, text=True)
        else:
            output = subprocess.check_output(['arp', '-n'], shell=True, text=True)
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ips = re.findall(ip_pattern, output)
        ips = [ip for ip in ips if not ip.startswith('224.') and not ip.startswith('255.') and ip != '0.0.0.0']
        ips = list(set(ips))
        for ip in ips:
            hostname = None
            try:
                if system == 'Windows':
                    result = subprocess.check_output(f'nslookup {ip}', shell=True, text=True)
                    match = re.search(r'Name:\s*(\S+)', result)
                    hostname = match.group(1) if match else ip
                else:
                    hostname = ip
            except:
                hostname = ip
            devices.append({'ip': ip, 'hostname': hostname})
    except Exception as e:
        print(f"Network discovery error: {e}")
    return devices

@app.route('/network_devices')
@login_required
def network_devices():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    devices = discover_network_devices()
    for dev in devices:
        db_dev = Device.query.filter_by(ip=dev['ip']).first()
        if db_dev:
            dev['first_seen'] = db_dev.first_seen
            dev['last_seen'] = db_dev.last_seen
            dev['log_count'] = Log.query.filter_by(src_ip=dev['ip']).count()
        else:
            dev['first_seen'] = None
            dev['last_seen'] = None
            dev['log_count'] = 0
    return render_template('network_devices.html', devices=devices)

# ============================================================
# 10. Manager/Admin Analysis Requests
# ============================================================
@app.route('/manager/request', methods=['GET', 'POST'])
@login_required
def manager_request():
    if current_user.role not in ['admin', 'manager']:
        flash('Unauthorized')
        return redirect(url_for('login'))
    if request.method == 'POST':
        req_message = request.form.get('request_message', '')
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            original_name = secure_filename(file.filename)
            stored_name = f"req_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex}_{original_name}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
            file.save(filepath)
            new_req = AnalysisRequest(
                manager_username=current_user.username,
                request_message=req_message,
                original_filename=original_name,
                stored_filename=stored_name,
                status='pending'
            )
            db.session.add(new_req)
            db.session.commit()
            flash('Analysis request sent to admin', 'success')
            return redirect(url_for('manager_requests'))
        else:
            flash('Please upload a valid file (.log, .txt, .csv)', 'error')
    return render_template('manager_request.html')

@app.route('/manager/requests')
@login_required
def manager_requests():
    if current_user.role not in ['admin', 'manager']:
        return redirect(url_for('login'))
    if current_user.role == 'admin':
        my_requests = AnalysisRequest.query.order_by(AnalysisRequest.created_at.desc()).all()
    else:
        my_requests = AnalysisRequest.query.filter_by(manager_username=current_user.username).order_by(AnalysisRequest.created_at.desc()).all()
    new_completed = AnalysisRequest.query.filter_by(manager_username=current_user.username, status='completed', is_read=False).count()
    return render_template('manager_requests.html', requests=my_requests, new_count=new_completed)

@app.route('/manager/view_report/<int:req_id>')
@login_required
def manager_view_report(req_id):
    req = AnalysisRequest.query.get_or_404(req_id)
    if current_user.role != 'admin' and req.manager_username != current_user.username:
        flash('Unauthorized', 'error')
        return redirect(url_for('manager_requests'))
    if req.status != 'completed':
        flash('Report not ready yet', 'error')
        return redirect(url_for('manager_requests'))
    if not req.is_read:
        req.is_read = True
        db.session.commit()
    return render_template('manager_report.html', req=req)

@app.route('/admin/requests')
@login_required
def admin_requests():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    all_requests = AnalysisRequest.query.order_by(AnalysisRequest.created_at.desc()).all()
    pending_count = AnalysisRequest.query.filter_by(status='pending').count()
    return render_template('admin_requests.html', requests=all_requests, pending_count=pending_count)

@app.route('/admin/analyze/<int:req_id>', methods=['POST'])
@login_required
def admin_analyze(req_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    req = AnalysisRequest.query.get_or_404(req_id)
    if req.status != 'pending':
        flash('This request has already been analyzed', 'warning')
        return redirect(url_for('admin_requests'))
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], req.stored_filename)
    if not os.path.exists(filepath):
        flash('File not found', 'error')
        return redirect(url_for('admin_requests'))
    try:
        req.status = 'analyzing'
        db.session.commit()
        report_data = analyze_uploaded_file(filepath, req.id)
        if not isinstance(report_data, dict):
            raise ValueError("Analysis returned invalid data type")
        total_lines = int(report_data.get('total_lines', 0))
        success = int(report_data.get('success', 0))
        failed = int(report_data.get('failed', 0))
        alerts = report_data.get('alerts') or []
        risk_score = int(report_data.get('risk_score', 0))
        if total_lines == 0 and success == 0 and failed == 0:
            raise ValueError("Invalid report data (empty analysis result)")
        req.status = 'completed'
        req.report_data = report_data
        req.report_generated_at = datetime.now(timezone.utc)
        req.risk_score = risk_score
        req.report_summary = f"Total lines: {total_lines} | Success: {success} | Failed: {failed} | Alerts: {len(alerts)} | Risk score: {risk_score}"
        db.session.commit()
        if risk_score >= 50:
            existing_risk = Risk.query.filter_by(title=f"Analysis of {req.original_filename}", status='Open').first()
            if existing_risk:
                req.risk_id = existing_risk.id
            else:
                new_risk = Risk(
                    title=f"Risk from analysis of {req.original_filename}",
                    description=f"Risk score {risk_score} due to suspicious activity or high failure rate.",
                    category="SIEM Analysis",
                    likelihood=min(5, max(1, round(risk_score / 20))),
                    impact=min(5, max(1, round(risk_score / 20))),
                    risk_response="Review and investigate",
                    owner="Admin",
                    status="Open"
                )
                new_risk.risk_score = new_risk.likelihood * new_risk.impact
                db.session.add(new_risk)
                db.session.commit()
                req.risk_id = new_risk.id
            db.session.commit()
        flash('File analyzed and report generated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        req.status = 'pending'
        db.session.commit()
        print(traceback.format_exc())
        flash('Error during analysis, check server logs', 'error')
    return redirect(url_for('admin_requests'))

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    all_users = User.query.all()
    return render_template('admin_users.html', users=all_users)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def admin_add_user():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    if not username or not password or role not in ['admin', 'manager']:
        flash('Invalid data')
        return redirect(url_for('admin_users'))
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect(url_for('admin_users'))
    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash(f'User {username} created successfully')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account')
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted')
    return redirect(url_for('admin_users'))

@app.route('/admin/alert/<int:alert_id>/link_risk', methods=['GET', 'POST'])
@login_required
def link_alert_risk(alert_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    alert = Alert.query.get_or_404(alert_id)
    risks = Risk.query.all()
    if request.method == 'POST':
        risk_id = request.form.get('risk_id')
        alert.risk_id = int(risk_id) if risk_id else None
        db.session.commit()
        flash(f'Alert #{alert.id} linked to risk {risk_id or "none"}')
        return redirect(url_for('view_alerts'))
    return render_template('link_alert_risk.html', alert=alert, risks=risks)

# ============================================================
# 11. GRC Modules – Unified Permissions
# ============================================================
def can_manage_policies():
    return current_user.role == 'manager'

def can_manage_other_grc():
    return current_user.role in ['admin', 'manager']

def can_view_grc():
    return current_user.role in ['admin', 'manager']

# ------------------------- Risks -------------------------
@app.route('/grc/risks')
@login_required
def grc_risks():
    if not can_view_grc():
        return redirect(url_for('report'))
    risks = Risk.query.order_by(Risk.risk_score.desc()).all()
    return render_template('grc/risks.html', risks=risks, can_edit=can_manage_other_grc())

@app.route('/grc/risks/add', methods=['GET', 'POST'])
@login_required
def grc_add_risk():
    if not can_manage_other_grc():
        flash('Only admins and managers can add risks', 'error')
        return redirect(url_for('grc_risks'))
    if request.method == 'POST':
        risk = Risk(
            title=request.form['title'],
            description=request.form['description'],
            category=request.form['category'],
            likelihood=int(request.form['likelihood']),
            impact=int(request.form['impact']),
            risk_response=request.form['risk_response'],
            owner=request.form['owner'],
            status=request.form['status']
        )
        risk.risk_score = risk.likelihood * risk.impact
        db.session.add(risk)
        db.session.commit()
        flash('Risk added successfully')
        return redirect(url_for('grc_risks'))
    return render_template('grc/risk_form.html')

@app.route('/grc/risks/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def grc_edit_risk(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can edit risks', 'error')
        return redirect(url_for('grc_risks'))
    risk = Risk.query.get_or_404(id)
    if request.method == 'POST':
        risk.title = request.form['title']
        risk.description = request.form['description']
        risk.category = request.form['category']
        risk.likelihood = int(request.form['likelihood'])
        risk.impact = int(request.form['impact'])
        risk.risk_score = risk.likelihood * risk.impact
        risk.risk_response = request.form['risk_response']
        risk.owner = request.form['owner']
        risk.status = request.form['status']
        db.session.commit()
        flash('Risk updated successfully')
        return redirect(url_for('grc_risks'))
    return render_template('grc/risk_form.html', risk=risk)

@app.route('/grc/risks/delete/<int:id>', methods=['POST'])
@login_required
def grc_delete_risk(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can delete risks', 'error')
        return redirect(url_for('grc_risks'))
    risk = Risk.query.get_or_404(id)
    db.session.delete(risk)
    db.session.commit()
    flash('Risk deleted successfully')
    return redirect(url_for('grc_risks'))

def classify_risk(text):
    text = (text or "").lower()
    if any(k in text for k in ["login", "password", "auth"]):
        if "brute" in text:
            return "Brute Force Attack"
        return "Authentication Risk"
    if any(k in text for k in ["xss", "script", "javascript"]):
        return "XSS Attack"
    if any(k in text for k in ["sql", "injection", "database"]):
        return "SQL Injection"
    if any(k in text for k in ["ddos", "flood", "traffic"]):
        return "DDoS Attack"
    if any(k in text for k in ["phishing", "email", "spoof"]):
        return "Phishing Attack"
    return "General Risk"

@app.route('/grc/risk_heatmap')
@login_required
def grc_heatmap():
    if not can_view_grc():
        return redirect(url_for('report'))
    risks = Risk.query.all()
    data = []
    for r in risks:
        full_text = (r.title or "") + " " + (r.description or "")
        data.append({
            "title": r.title,
            "likelihood": int(r.likelihood),
            "impact": int(r.impact),
            "risk_score": r.risk_score or (r.likelihood * r.impact),
            "category": classify_risk(full_text)
        })
    return render_template("grc/heatmap.html", risks=data)

# ------------------------- Policies (Manager only) -------------------------
@app.route('/grc/policies')
@login_required
def grc_policies():
    if not can_view_grc():
        return redirect(url_for('report'))
    policies = Policy.query.order_by(Policy.last_updated.desc()).all()
    for policy in policies:
        policy.mark_as_read_by(current_user)
    return render_template('grc/policies.html', policies=policies, can_edit=can_manage_policies())

@app.route('/grc/policies/add', methods=['GET', 'POST'])
@login_required
def grc_add_policy():
    if not can_manage_policies():
        flash('Only managers can create policies', 'error')
        return redirect(url_for('grc_policies'))
    if request.method == 'POST':
        policy = Policy(
            title=request.form['title'],
            policy_type=request.form.get('policy_type', ''),
            version=request.form.get('version', ''),
            summary=request.form.get('summary', ''),
            full_content=request.form.get('full_content', ''),
            approved_by=request.form.get('approved_by', ''),
            status='Active',
            created_by_id=current_user.id,
            last_updated_by_id=current_user.id
        )
        if request.form.get('last_reviewed'):
            policy.last_reviewed = datetime.strptime(request.form['last_reviewed'], '%Y-%m-%d')
        if request.form.get('next_review'):
            policy.next_review = datetime.strptime(request.form['next_review'], '%Y-%m-%d')
        db.session.add(policy)
        db.session.commit()
        policy.mark_as_read_by(current_user)
        flash('Policy added successfully', 'success')
        return redirect(url_for('grc_policies'))
    return render_template('grc/policy_form.html')

@app.route('/grc/policies/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def grc_edit_policy(id):
    if not can_manage_policies():
        flash('Only managers can edit policies', 'error')
        return redirect(url_for('grc_policies'))
    policy = Policy.query.get_or_404(id)
    if request.method == 'POST':
        policy.title = request.form['title']
        policy.policy_type = request.form.get('policy_type')
        policy.version = request.form.get('version')
        policy.summary = request.form.get('summary')
        policy.full_content = request.form.get('full_content')
        policy.approved_by = request.form.get('approved_by')
        policy.last_updated_by_id = current_user.id
        policy.last_updated = datetime.now(timezone.utc)
        if request.form.get('last_reviewed'):
            policy.last_reviewed = datetime.strptime(request.form['last_reviewed'], '%Y-%m-%d')
        if request.form.get('next_review'):
            policy.next_review = datetime.strptime(request.form['next_review'], '%Y-%m-%d')
        db.session.commit()
        flash('Policy updated successfully', 'success')
        return redirect(url_for('grc_policies'))
    return render_template('grc/policy_form.html', policy=policy)

@app.route('/grc/policies/<int:id>/delete', methods=['POST'])
@login_required
def grc_delete_policy(id):
    if not can_manage_policies():
        flash('Only managers can delete policies', 'error')
        return redirect(url_for('grc_policies'))
    policy = Policy.query.get_or_404(id)
    PolicyRead.query.filter_by(policy_id=id).delete()
    db.session.delete(policy)
    db.session.commit()
    flash('Policy deleted successfully', 'success')
    return redirect(url_for('grc_policies'))

@app.route('/grc/policy/<int:id>/read')
@login_required
def grc_mark_policy_read(id):
    policy = Policy.query.get_or_404(id)
    policy.mark_as_read_by(current_user)
    flash(f'Policy "{policy.title}" marked as read.', 'success')
    return redirect(url_for('grc_policies'))

@app.route('/grc/policy/<int:id>')
@login_required
def grc_policy_view(id):
    if not can_view_grc():
        flash('Access denied', 'error')
        return redirect(url_for('grc_dashboard'))
    policy = Policy.query.get_or_404(id)
    policy.mark_as_read_by(current_user)
    return render_template('grc/policy_details.html', policy=policy)

# ------------------------- Compliance (Admin+Manager) -------------------------
@app.route('/grc/compliance')
@login_required
def grc_compliance():
    if not can_view_grc():
        return redirect(url_for('report'))
    reqs = ComplianceRequirement.query.all()
    total = len(reqs)
    compliant = sum(1 for r in reqs if r.current_status == 'Compliant')
    partial = sum(1 for r in reqs if r.current_status == 'Partial')
    non_compliant = sum(1 for r in reqs if r.current_status == 'Non-Compliant')
    return render_template('grc/compliance.html', requirements=reqs, total=total,
                           compliant=compliant, partial=partial, non_compliant=non_compliant,
                           can_edit=can_manage_other_grc())

@app.route('/grc/compliance/add', methods=['GET', 'POST'])
@login_required
def grc_add_compliance():
    if not can_manage_other_grc():
        flash('Only admins and managers can add compliance requirements', 'error')
        return redirect(url_for('grc_compliance'))
    if request.method == 'POST':
        req = ComplianceRequirement(
            standard=request.form['standard'], req_id=request.form['req_id'],
            description=request.form['description'], current_status=request.form['current_status'],
            evidence=request.form['evidence'], remediation_plan=request.form['remediation_plan']
        )
        if request.form.get('target_completion'):
            req.target_completion = datetime.strptime(request.form['target_completion'], '%Y-%m-%d')
        db.session.add(req)
        db.session.commit()
        flash('Compliance requirement added')
        return redirect(url_for('grc_compliance'))
    return render_template('grc/compliance_form.html')

@app.route('/grc/compliance/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def grc_edit_compliance(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can edit compliance requirements', 'error')
        return redirect(url_for('grc_compliance'))
    req = ComplianceRequirement.query.get_or_404(id)
    if request.method == 'POST':
        req.standard = request.form['standard']
        req.req_id = request.form['req_id']
        req.description = request.form['description']
        req.current_status = request.form['current_status']
        req.evidence = request.form['evidence']
        req.remediation_plan = request.form['remediation_plan']
        if request.form.get('target_completion'):
            req.target_completion = datetime.strptime(request.form['target_completion'], '%Y-%m-%d')
        db.session.commit()
        flash('Requirement updated')
        return redirect(url_for('grc_compliance'))
    return render_template('grc/compliance_form.html', req=req)

@app.route('/grc/compliance/delete/<int:id>')
@login_required
def grc_delete_compliance(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can delete compliance requirements', 'error')
        return redirect(url_for('grc_compliance'))
    req = ComplianceRequirement.query.get_or_404(id)
    db.session.delete(req)
    db.session.commit()
    flash('Requirement deleted')
    return redirect(url_for('grc_compliance'))

# ------------------------- Incidents (Admin+Manager) -------------------------
@app.route('/grc/incidents')
@login_required
def grc_incidents():
    if not can_view_grc():
        return redirect(url_for('report'))
    incidents = Incident.query.order_by(Incident.detection_time.desc()).all()
    return render_template('grc/incidents.html', incidents=incidents, can_edit=can_manage_other_grc())

@app.route('/grc/incidents/add', methods=['GET', 'POST'])
@login_required
def grc_add_incident():
    if not can_manage_other_grc():
        flash('Only admins and managers can add incidents', 'error')
        return redirect(url_for('grc_incidents'))
    if request.method == 'POST':
        detection_time_str = request.form.get('detection_time', '')
        if detection_time_str:
            detection_time = datetime.strptime(detection_time_str, '%Y-%m-%dT%H:%M')
        else:
            detection_time = datetime.now(timezone.utc)
        containment_time = None
        if request.form.get('containment_time'):
            containment_time = datetime.strptime(request.form['containment_time'], '%Y-%m-%dT%H:%M')
        resolution_time = None
        if request.form.get('resolution_time'):
            resolution_time = datetime.strptime(request.form['resolution_time'], '%Y-%m-%dT%H:%M')
        inc = Incident(
            title=request.form['title'],
            severity=request.form['severity'],
            description=request.form['description'],
            detection_time=detection_time,
            containment_time=containment_time,
            resolution_time=resolution_time,
            assignee=request.form.get('assignee', ''),
            status=request.form['status']
        )
        db.session.add(inc)
        db.session.commit()
        flash('Incident added successfully', 'success')
        return redirect(url_for('grc_incidents'))
    return render_template('grc/incident_form.html')

@app.route('/grc/incidents/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def grc_edit_incident(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can edit incidents', 'error')
        return redirect(url_for('grc_incidents'))
    inc = Incident.query.get_or_404(id)
    if request.method == 'POST':
        inc.title = request.form['title']
        inc.severity = request.form['severity']
        inc.description = request.form['description']
        inc.detection_time = datetime.strptime(request.form['detection_time'], '%Y-%m-%dT%H:%M')
        inc.assignee = request.form['assignee']
        inc.status = request.form['status']
        if request.form.get('containment_time'):
            inc.containment_time = datetime.strptime(request.form['containment_time'], '%Y-%m-%dT%H:%M')
        if request.form.get('resolution_time'):
            inc.resolution_time = datetime.strptime(request.form['resolution_time'], '%Y-%m-%dT%H:%M')
        db.session.commit()
        flash('Incident updated')
        return redirect(url_for('grc_incidents'))
    return render_template('grc/incident_form.html', incident=inc)

@app.route('/grc/incidents/delete/<int:id>')
@login_required
def grc_delete_incident(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can delete incidents', 'error')
        return redirect(url_for('grc_incidents'))
    inc = Incident.query.get_or_404(id)
    db.session.delete(inc)
    db.session.commit()
    flash('Incident deleted')
    return redirect(url_for('grc_incidents'))

# ------------------------- BCP / Critical Systems (Admin+Manager) -------------------------
@app.route('/grc/bcp')
@login_required
def grc_bcp():
    if not can_view_grc():
        return redirect(url_for('report'))
    systems = CriticalSystem.query.all()
    return render_template('grc/bcp.html', systems=systems, can_edit=can_manage_other_grc())

@app.route('/grc/bcp/add', methods=['GET', 'POST'])
@login_required
def grc_add_system():
    if not can_manage_other_grc():
        flash('Only admins and managers can add critical systems', 'error')
        return redirect(url_for('grc_bcp'))
    if request.method == 'POST':
        sys = CriticalSystem(
            name=request.form['name'], description=request.form['description'],
            rto=int(request.form['rto']), rpo=int(request.form['rpo']),
            backup_frequency=request.form['backup_frequency'], owner=request.form['owner']
        )
        db.session.add(sys)
        db.session.commit()
        flash('Critical system added')
        return redirect(url_for('grc_bcp'))
    return render_template('grc/system_form.html')

@app.route('/grc/bcp/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def grc_edit_system(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can edit critical systems', 'error')
        return redirect(url_for('grc_bcp'))
    sys = CriticalSystem.query.get_or_404(id)
    if request.method == 'POST':
        sys.name = request.form['name']
        sys.description = request.form['description']
        sys.rto = int(request.form['rto'])
        sys.rpo = int(request.form['rpo'])
        sys.backup_frequency = request.form['backup_frequency']
        sys.owner = request.form['owner']
        db.session.commit()
        flash('System updated')
        return redirect(url_for('grc_bcp'))
    return render_template('grc/system_form.html', system=sys)

@app.route('/grc/bcp/delete/<int:id>')
@login_required
def grc_delete_system(id):
    if not can_manage_other_grc():
        flash('Only admins and managers can delete critical systems', 'error')
        return redirect(url_for('grc_bcp'))
    sys = CriticalSystem.query.get_or_404(id)
    db.session.delete(sys)
    db.session.commit()
    flash('System deleted')
    return redirect(url_for('grc_bcp'))

# ------------------------- KPI & GRC Dashboard (View only) -------------------------
@app.route('/grc/kpi')
@login_required
def grc_kpi():
    if not can_view_grc():
        return redirect(url_for('report'))
    last_month = datetime.now(timezone.utc) - timedelta(days=30)
    total_incidents = Incident.query.filter(Incident.detection_time >= last_month).count()
    high_incidents = Incident.query.filter(Incident.severity == 'High', Incident.detection_time >= last_month).count()
    mttd = calculate_mttd()
    open_risks = Risk.query.filter_by(status='Open').count()
    total_reqs = ComplianceRequirement.query.count()
    compliant_reqs = ComplianceRequirement.query.filter_by(current_status='Compliant').count()
    compliance_score = (compliant_reqs / total_reqs * 100) if total_reqs else 0
    return render_template('grc/kpi.html', total_incidents=total_incidents, high_incidents=high_incidents,
                           mttd=mttd, mttr=0, open_risks=open_risks, compliance_score=compliance_score)

@app.route('/grc/dashboard')
@login_required
def grc_dashboard():
    if not can_view_grc():
        return redirect(url_for('report'))
    risk_high = Risk.query.filter(Risk.risk_score >= 15).count()
    incident_critical = Incident.query.filter_by(severity='Critical', status='Open').count()
    non_compliant = ComplianceRequirement.query.filter_by(current_status='Non-Compliant').count()
    policies_due = Policy.query.filter(Policy.next_review <= datetime.now(timezone.utc).date()).count()
    return render_template('grc/dashboard.html', risk_high=risk_high, incident_critical=incident_critical,
                           non_compliant=non_compliant, policies_due=policies_due)

# ============================================================
# 12. PDF Reports (unchanged)
# ============================================================
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics, ttfonts
from reportlab.lib.enums import TA_LEFT, TA_CENTER

@app.route('/report/pdf')
@login_required
def report_pdf():
    total_logs = Log.query.count()
    total_alerts = Alert.query.count()
    success_count = Log.query.filter_by(status='success').count()
    failed_count = Log.query.filter_by(status='failed').count()
    event_types = db.session.query(Log.event_type, func.count(Log.id)).group_by(Log.event_type).all()
    event_type_data = [["Event Type", "Count"]] + [[et, str(cnt)] for et, cnt in event_types]
    severity_counts = db.session.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_data = [["Severity", "Count"]] + [[sev, str(cnt)] for sev, cnt in severity_counts]
    failed_logins = db.session.query(Log.src_ip, func.count(Log.id)).filter(
        Log.event_type == 'login', Log.status == 'failed').group_by(Log.src_ip).order_by(
        func.count(Log.id).desc()).limit(5).all()
    top_failed_ips = [["IP", "Failed Attempts"]] + [[ip, str(cnt)] for ip, cnt in failed_logins] if failed_logins else [["No failed logins found", ""]]
    top_ips_all = db.session.query(Log.src_ip, func.count(Log.id)).group_by(Log.src_ip).order_by(
        func.count(Log.id).desc()).limit(5).all()
    top_ips_data = [["IP", "Total Logs"]] + [[ip, str(cnt)] for ip, cnt in top_ips_all]
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    recent_alerts_data = [["Timestamp", "Severity", "Rule", "Description"]]
    for a in recent_alerts:
        recent_alerts_data.append(
            [a.timestamp.strftime('%Y-%m-%d %H:%M:%S'), a.severity, a.rule_name,
             a.description[:80] + ("..." if len(a.description) > 80 else "")])
    success_rate = (success_count / total_logs * 100) if total_logs else 0
    stats_data = [["Total Logs", str(total_logs)], ["Total Alerts", str(total_alerts)],
                  ["Success Count", str(success_count)], ["Failed Count", str(failed_count)],
                  ["Success Rate", f"{success_rate:.1f}%"]]
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    try:
        pdfmetrics.registerFont(ttfonts.TTFont('Arial', 'C:/Windows/Fonts/arial.ttf'))
        font_name = 'Arial'
    except:
        font_name = 'Helvetica'
    styles = getSampleStyleSheet()
    style_normal = ParagraphStyle('Normal', parent=styles['Normal'], alignment=TA_LEFT, fontName=font_name, fontSize=10)
    style_header = ParagraphStyle('Header', parent=styles['Heading2'], alignment=TA_LEFT, fontName=font_name, fontSize=12,
                                  textColor=colors.HexColor('#0f6bff'))
    style_title = ParagraphStyle('Title', parent=styles['Title'], alignment=TA_CENTER, fontName=font_name, fontSize=16)
    elements = []
    elements.append(Paragraph("SIEM Security Report", style_title))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC", style_normal))
    elements.append(Paragraph(f"User: {current_user.username} (Role: {current_user.role})", style_normal))
    if current_user.role == 'manager':
        elements.append(Paragraph("Note: You can request a deeper analysis by submitting a log file to the admin.",
                                  style_normal))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("1. Overall Statistics", style_header))
    stats_table = Table(stats_data, colWidths=[120, 80])
    stats_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("2. Events by Type", style_header))
    event_table = Table(event_type_data, colWidths=[120, 80])
    event_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue)
    ]))
    elements.append(event_table)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("3. Alert Severity Distribution", style_header))
    severity_table = Table(severity_data, colWidths=[120, 80])
    severity_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightcoral)
    ]))
    elements.append(severity_table)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("4. Top 5 Source IPs (All Events)", style_header))
    top_ips_table = Table(top_ips_data, colWidths=[120, 80])
    top_ips_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightyellow)
    ]))
    elements.append(top_ips_table)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("5. Top 5 IPs with Failed Logins", style_header))
    failed_ips_table = Table(top_failed_ips, colWidths=[120, 80])
    failed_ips_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightyellow)
    ]))
    elements.append(failed_ips_table)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("6. Recent Alerts (Last 5)", style_header))
    alert_table = Table(recent_alerts_data, colWidths=[80, 50, 70, 110])
    alert_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen)
    ]))
    elements.append(alert_table)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("7. Recommendations", style_header))
    recs = [
        "- Regularly review failed login attempts; consider rate limiting or account lockout policies.",
        "- Monitor top IPs for unusual activity; add suspicious IPs to blacklist.",
        "- Keep detection rules updated to catch new attack patterns.",
        "- For deeper analysis, managers can submit log files to the admin via the request system."
    ]
    for rec in recs:
        elements.append(Paragraph(rec, style_normal))
        elements.append(Spacer(1, 4))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("This report was generated automatically by the SIEM system.", style_normal))
    doc.build(elements)
    pdf_data = buffer.getvalue()
    buffer.close()
    response = make_response(pdf_data)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=siem_report.pdf'
    return response

@app.route('/grc/report/pdf')
@login_required
def grc_report_pdf():
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=50, bottomMargin=40)
    styles = getSampleStyleSheet()
    try:
        pdfmetrics.registerFont(ttfonts.TTFont('Arial', 'C:/Windows/Fonts/arial.ttf'))
        font_name = 'Arial'
    except:
        font_name = 'Helvetica'
    style_title = ParagraphStyle('Title', parent=styles['Title'], alignment=TA_CENTER, fontName=font_name, fontSize=16,
                                 spaceAfter=20)
    style_heading = ParagraphStyle('Heading', parent=styles['Heading2'], fontName=font_name, fontSize=12,
                                   textColor=colors.HexColor('#0f6bff'), spaceAfter=8, spaceBefore=12)
    style_normal = ParagraphStyle('Normal', parent=styles['Normal'], fontName=font_name, fontSize=9, leading=12)
    elements = []
    elements.append(Paragraph("Governance, Risk & Compliance (GRC) Report", style_title))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC", style_normal))
    elements.append(Paragraph(f"User: {current_user.username} (Role: {current_user.role})", style_normal))
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("1. Risk Register", style_heading))
    risks = Risk.query.order_by(Risk.risk_score.desc()).all()
    if risks:
        data = [["Title", "L", "I", "Score", "Response", "Owner"]]
        for r in risks:
            title_text = r.title[:50] + "..." if len(r.title) > 50 else r.title
            response_text = (r.risk_response[:20] + "...") if r.risk_response and len(r.risk_response) > 20 else (r.risk_response or "-")
            owner_text = (r.owner[:25] + "...") if r.owner and len(r.owner) > 25 else (r.owner or "-")
            data.append([title_text, str(r.likelihood), str(r.impact), str(r.risk_score), response_text, owner_text])
        table = Table(data, colWidths=[90, 15, 15, 25, 50, 55], repeatRows=1)
        table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f6bff')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ALIGN', (1, 0), (3, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No risks defined.", style_normal))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("2. Compliance Requirements", style_heading))
    reqs = ComplianceRequirement.query.all()
    if reqs:
        data = [["Standard", "ID", "Description", "Status", "Remediation"]]
        for cr in reqs:
            desc = cr.description[:70] + "..." if len(cr.description) > 70 else cr.description
            remed = (cr.remediation_plan[:60] + "...") if cr.remediation_plan and len(cr.remediation_plan) > 60 else (cr.remediation_plan or "-")
            data.append([cr.standard, cr.req_id, desc, cr.current_status, remed])
        table = Table(data, colWidths=[60, 40, 130, 50, 90], repeatRows=1)
        table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ecc71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No compliance requirements.", style_normal))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("3. Incident Management", style_heading))
    incidents = Incident.query.order_by(Incident.detection_time.desc()).limit(10).all()
    if incidents:
        data = [["Title", "Severity", "Detection Time", "Status", "Assignee"]]
        for inc in incidents:
            title_short = inc.title[:40] + "..." if len(inc.title) > 40 else inc.title
            data.append([title_short, inc.severity,
                         inc.detection_time.strftime('%Y-%m-%d %H:%M') if inc.detection_time else '-', inc.status,
                         inc.assignee or '-'])
        table = Table(data, colWidths=[100, 45, 70, 50, 70], repeatRows=1)
        table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e67e22')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No incidents recorded.", style_normal))
    mttd = calculate_mttd()
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"<b>MTTD (Mean Time To Detect):</b> {mttd} seconds", style_normal))
    elements.append(Paragraph(f"<b>Total incidents recorded:</b> {Incident.query.count()}", style_normal))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("4. Business Continuity & Disaster Recovery", style_heading))
    systems = CriticalSystem.query.all()
    if systems:
        data = [["System Name", "RTO (min)", "RPO (min)", "Backup Frequency", "Owner"]]
        for s in systems:
            data.append([s.name[:45] + "..." if len(s.name) > 45 else s.name, str(s.rto), str(s.rpo),
                         s.backup_frequency[:50] if s.backup_frequency else '-', s.owner[:30] if s.owner else '-'])
        table = Table(data, colWidths=[110, 45, 45, 100, 80], repeatRows=1)
        table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("No critical systems defined.", style_normal))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("5. Recommendations", style_heading))
    recs = [
        "• Review high-risk items (score ≥ 15) with owners and implement mitigation actions.",
        "• Address non-compliant compliance requirements according to remediation plans.",
        "• Conduct regular incident response drills to improve MTTD.",
        "• Test Business Continuity plans annually to validate RTO/RPO targets.",
        "• Use the SIEM dashboard for continuous risk monitoring and KPI tracking."
    ]
    for rec in recs:
        elements.append(Paragraph(rec, style_normal))
        elements.append(Spacer(1, 4))
    doc.build(elements)
    pdf_data = buffer.getvalue()
    buffer.close()
    response = make_response(pdf_data)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=grc_report.pdf'
    return response

# ============================================================
# 13. Database Upgrade and Start
# ============================================================
def upgrade_database_safe():
    try:
        conn = sqlite3.connect('siem.db')
        cursor = conn.cursor()
        for table in ['user', 'analysis_request', 'risk', 'log', 'alert', 'policy']:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if cursor.fetchone():
                cursor.execute(f"PRAGMA table_info({table})")
                cols = [c[1] for c in cursor.fetchall()]
                if table == 'user' and 'accepted_policies' not in cols:
                    cursor.execute("ALTER TABLE user ADD COLUMN accepted_policies BOOLEAN DEFAULT 0")
                if table == 'analysis_request':
                    if 'risk_score' not in cols:
                        cursor.execute("ALTER TABLE analysis_request ADD COLUMN risk_score INTEGER")
                    if 'risk_id' not in cols:
                        cursor.execute("ALTER TABLE analysis_request ADD COLUMN risk_id INTEGER")
                    if 'is_read' not in cols:
                        cursor.execute("ALTER TABLE analysis_request ADD COLUMN is_read BOOLEAN DEFAULT 0")
                if table == 'risk' and 'created_at' not in cols:
                    cursor.execute("ALTER TABLE risk ADD COLUMN created_at TIMESTAMP")
                if table == 'log':
                    for col in ['request_path', 'method', 'user_agent']:
                        if col not in cols:
                            try:
                                cursor.execute(f"ALTER TABLE log ADD COLUMN {col} TEXT")
                            except:
                                pass
                if table == 'alert' and 'risk_id' not in cols:
                    cursor.execute("ALTER TABLE alert ADD COLUMN risk_id INTEGER")
                if table == 'policy' and 'status' not in cols:
                    cursor.execute("ALTER TABLE policy ADD COLUMN status TEXT DEFAULT 'Active'")
        conn.commit()
        conn.close()
    except Exception as e:
        print("Database upgrade warning:", e)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        upgrade_database_safe()

        # التأكد من أن جميع المستخدمين لديهم حقل accepted_policies بقيمة False إذا كان None
        for user in User.query.all():
            if hasattr(user, 'accepted_policies') and user.accepted_policies is None:
                user.accepted_policies = False

        # إنشاء المستخدمين الافتراضيين إذا لم يكونوا موجودين
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            admin.accepted_policies = False
            db.session.add(admin)
        if not User.query.filter_by(username='manager1').first():
            manager = User(username='manager1', role='manager')
            manager.set_password('manager123')
            manager.accepted_policies = False
            db.session.add(manager)

        # إنشاء سياسة افتراضية نشطة إذا لم توجد أي سياسة
        if not Policy.query.first():
            # الحصول على أول مستخدم (عادةً admin) لربط السياسة به
            first_user = User.query.first()
            if first_user:
                default_policy = Policy(
                    title="سياسة الأمن الأساسية",
                    policy_type="أمن المعلومات",
                    version="1.0",
                    summary="هذه سياسة إلزامية يجب الموافقة عليها للوصول إلى النظام.",
                    full_content="""يسعدنا انضمامك إلى نظام SIEM/GRC. للحفاظ على بيئة عمل آمنة، يرجى الالتزام بالسياسات التالية:

1. الحفاظ على سرية كلمات المرور وعدم مشاركتها.
2. الإبلاغ الفوري عن أي سلوك مشبوه أو خرق أمني.
3. استخدام النظام فقط للأغراض المصرح بها.
4. اتباع إجراءات الوصول المحددة في دليل المستخدم.

الموافقة على هذه السياسة تعني فهمك والتزامك بها.""",
                    status="Active",
                    created_by_id=first_user.id,
                    last_updated_by_id=first_user.id
                )
                db.session.add(default_policy)
                print("[INFO] تم إنشاء سياسة افتراضية نشطة بنجاح.")
            else:
                print("[WARN] لا يوجد مستخدم لربط السياسة الافتراضية، لن يتم إنشاء السياسة.")

        # إعادة تعيين حالة الموافقة لجميع المستخدمين إلى False (لإجبارهم على الموافقة عند أول دخول)
        # (يمكنك التعليق على هذا السطر إذا كنت لا تريد إعادة تعيين القيم الموجودة)
        User.query.update({User.accepted_policies: False})
        db.session.commit()
        print("[INFO] تم إعادة تعيين حالة الموافقة على السياسات لجميع المستخدمين.")

    # بدء الخيوط الخلفية
    start_agent_thread()
    threading.Thread(target=socket_batch_worker, daemon=True).start()
    print("Default users: admin/admin123 , manager1/manager123")
    print("Server running at http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)