from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from pdf_generator import generate_report_pdf
from flask import make_response
import os
import re
import sqlite3
import subprocess
import platform
import threading
import time
from collections import defaultdict
from werkzeug.utils import secure_filename
from models import db, Log, Alert, Device, UserActivity, NetworkConnection, NetworkAlert, User, AnalysisRequest
from rules import apply_detection_rules

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///siem.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = './uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- Global flags for sniffer & agent ----------
sniffer_active = False
sniffer_thread = None
sniffer_interface = None

agent_active = False
temp_connections = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': None})
temp_lock = threading.Lock()

# ---------- Database upgrade & default users ----------
def upgrade_database_safe():
    try:
        conn = sqlite3.connect('siem.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='log'")
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(log)")
            columns = [col[1] for col in cursor.fetchall()]
            for col in ['request_path', 'method', 'user_agent']:
                if col not in columns:
                    try:
                        cursor.execute(f"ALTER TABLE log ADD COLUMN {col} VARCHAR(200)")
                    except:
                        pass
        conn.commit()
        conn.close()
    except Exception as e:
        print("Database upgrade:", e)

with app.app_context():
    db.create_all()
    upgrade_database_safe()
    # Create default admin and manager if they don't exist
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
    if not User.query.filter_by(username='manager1').first():
        manager = User(username='manager1', role='manager')
        manager.set_password('manager123')
        db.session.add(manager)
    db.session.commit()
    print("Default users: admin/admin123 , manager1/manager123")

# ---------- Helper functions (log parsing, device update) ----------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def parse_log_line(line):
    entry = {
        'src_ip': None,
        'username': None,
        'timestamp': None,
        'event_type': 'unknown',
        'status': None,
        'details': line.strip(),
        'request_path': None,
        'method': None,
        'user_agent': None
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
        dev.last_seen = datetime.utcnow()
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
        timestamp=parsed['timestamp'] or datetime.utcnow(),
        src_ip=parsed['src_ip'],
        username=parsed['username'],
        event_type=parsed['event_type'],
        status=parsed['status'],
        details=parsed['details'],
        request_path=parsed['request_path'],
        method=parsed['method'],
        user_agent=parsed['user_agent']
    )
    db.session.add(log)
    db.session.commit()
    update_device(parsed['src_ip'])
    alerts = apply_detection_rules(log)
    for alert in alerts:
        db.session.add(alert)
    db.session.commit()
    return log

# ---------- Analysis function for uploaded file (used by admin) ----------
def analyze_uploaded_file(filepath, request_id):
    """Analyzes a log file and returns a report dict with statistics, alerts, and recommendations."""
    total_lines = 0
    success_count = 0
    failed_count = 0
    top_ips = defaultdict(int)
    event_types = defaultdict(int)
    # We'll collect alerts that are generated during analysis
    # But alerts are already stored in DB; we can retrieve them after processing.
    # We'll process the file line by line using process_log_line which creates logs and alerts.
    # However that would add data to the main logs table. To avoid duplication, we will parse
    # without saving to DB? But the requirement is to use the same analysis engine.
    # For simplicity, we use process_log_line but we might want to separate? 
    # Actually manager requests are additional analysis, it's fine to add those logs to the system.
    # But to avoid mixing with regular logs, we could use a flag. We'll still add them.
    # We'll run process_log_line for each line; it will create Log entries and Alerts.
    # At the end we collect stats from the database for the lines we just added? Hard.
    # Better to parse manually without saving? But then detection rules won't run.
    # I'll use process_log_line but also store the request_id in a temporary way?
    # We'll just use process_log_line and after processing we query the most recent alerts
    # that match the IPs seen.
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                log = process_log_line(line, source=f'request_{request_id}')
                if log.status == 'success':
                    success_count += 1
                elif log.status == 'failed':
                    failed_count += 1
                if log.src_ip:
                    top_ips[log.src_ip] += 1
                event_types[log.event_type] += 1
    except Exception as e:
        print(f"Error analyzing file: {e}")
        return None

    # Retrieve alerts related to this analysis (the most recent alerts that involve the IPs seen)
    # We'll take top 20 alerts ordered by timestamp desc and filter by those IPs
    alerts_list = []
    if top_ips:
        recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
        for alert in recent_alerts:
            if alert.src_ip in top_ips:
                alerts_list.append({
                    'severity': alert.severity,
                    'rule': alert.rule_name,
                    'desc': alert.description,
                    'ip': alert.src_ip,
                    'time': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                })
    # Generate recommendations
    recommendations = []
    if failed_count > success_count and success_count > 0:
        recommendations.append("نسبة الفشل عالية جداً - تأكد من صحة محاولات الدخول or there may be an attack.")
    if any(et for et in event_types if 'login' in et and event_types[et] > 10):
        recommendations.append("كثرة محاولات الدخول قد تشير إلى هجوم تخمين كلمات المرور. فعّل سياسة القفل المؤقت أو استخدم CAPTCHA.")
    high_freq_ips = [ip for ip, cnt in top_ips.items() if cnt > 20]
    if high_freq_ips:
        recommendations.append(f"هناك عناوين IP تظهر بشكل متكرر: {', '.join(high_freq_ips[:3])}. قم بفحصها وإضافتها إلى القائمة السوداء إذا كانت مشبوهة.")
    if not recommendations:
        recommendations.append("لا توجد توصيات خاصة بناءً على التحليل الحالي. استمر في المراقبة الدورية.")
    # Add a generic recommendation
    recommendations.append("تحديث قواعد الكشف بانتظام ومراجعة السجلات الدورية للحفاظ على أمان النظام.")

    report_data = {
        'total_lines': total_lines,
        'success': success_count,
        'failed': failed_count,
        'top_ips': dict(sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
        'event_types': dict(event_types),
        'alerts': alerts_list[:20],
        'recommendations': recommendations
    }
    return report_data

# ---------- Authentication routes ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
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

# ---------- Admin‑only pages (full access) ----------
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
    from sqlalchemy import func
    top_attackers = db.session.query(Alert.src_ip, func.count(Alert.id)).filter(Alert.src_ip.isnot(None)).group_by(Alert.src_ip).order_by(func.count(Alert.id).desc()).limit(5).all()
    return render_template('index.html', total_logs=total_logs, total_alerts=total_alerts,
                           success_logs=success_logs, failed_logs=failed_logs, devices_count=devices_count,
                           recent_alerts=recent_alerts, top_attackers=top_attackers)

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

@app.route('/submit_log', methods=['GET','POST'])
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
        for a in alerts:
            db.session.add(a)
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
            'ip': dev.ip, 'hostname': dev.hostname, 'first_seen': dev.first_seen, 'last_seen': dev.last_seen,
            'success_count': success_cnt, 'failed_count': failed_cnt,
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

# ---------- Sniffer & Agent control (admin only) ----------
@app.route('/start_sniffer', methods=['POST'])
@login_required
def start_sniffer():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    global sniffer_active, sniffer_thread, sniffer_interface
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
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    global sniffer_active
    sniffer_active = False
    return jsonify({'status': 'Sniffer stopped'})

@app.route('/sniffer_status')
@login_required
def sniffer_status():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({'active': sniffer_active, 'interface': sniffer_interface})

@app.route('/sniffer')
@login_required
def sniffer_page():
    if current_user.role != 'admin':
        return redirect(url_for('report'))
    return render_template('sniffer.html')

@app.route('/start_agent', methods=['POST'])
@login_required
def start_agent():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    global agent_active
    if agent_active:
        return jsonify({'status': 'Agent already running'}), 400
    agent_active = True
    threading.Thread(target=agent_send_connections, daemon=True).start()
    threading.Thread(target=advanced_threat_analysis, daemon=True).start()
    return jsonify({'status': 'Agent started'})

@app.route('/stop_agent', methods=['POST'])
@login_required
def stop_agent():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    global agent_active
    agent_active = False
    return jsonify({'status': 'Agent stopped'})

@app.route('/agent_status')
@login_required
def agent_status():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({'active': agent_active})

# ---------- External API (no login required, used by external agent) ----------
@app.route('/api/agent/connections', methods=['POST'])
def agent_connections():
    data = request.json
    if not data:
        return jsonify({'error': 'No data'}), 400
    agent_id = data.get('agent_id', 'unknown')
    connections_list = data.get('connections', [])
    for conn_data in connections_list:
        conn = NetworkConnection(
            timestamp=datetime.fromisoformat(conn_data['last_seen']) if conn_data.get('last_seen') else datetime.utcnow(),
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

# ---------- Network monitoring pages (admin only) ----------
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
    return render_template('network_connections.html', connections=connections, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)

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
                    if match:
                        hostname = match.group(1)
                    else:
                        hostname = ip
                else:
                    hostname = ip
            except:
                hostname = ip
            devices.append({'ip': ip, 'hostname': hostname})
    except Exception as e:
        print(f"خطأ في اكتشاف الشبكة: {e}")
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

# ---------- Manager & Admin Analysis Request System ----------
# Manager: submit request
@app.route('/manager/request', methods=['GET', 'POST'])
@login_required
def manager_request():
    if current_user.role not in ['admin', 'manager']:
        flash('غير مصرح')
        return redirect(url_for('login'))
    if request.method == 'POST':
        req_message = request.form.get('request_message', '')
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            original_name = secure_filename(file.filename)
            stored_name = f"req_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{original_name}"
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
            flash('تم إرسال طلب التحليل إلى المسؤول بنجاح')
            return redirect(url_for('manager_requests'))
        else:
            flash('يرجى رفع ملف صالح (.log, .txt, .csv)')
    return render_template('manager_request.html')

# Manager: list his requests
@app.route('/manager/requests')
@login_required
def manager_requests():
    if current_user.role not in ['admin', 'manager']:
        return redirect(url_for('login'))
    my_requests = AnalysisRequest.query.filter_by(manager_username=current_user.username).order_by(AnalysisRequest.created_at.desc()).all()
    new_completed = AnalysisRequest.query.filter_by(manager_username=current_user.username, status='completed', is_read=False).count()
    return render_template('manager_requests.html', requests=my_requests, new_count=new_completed)

# Manager: view full report
@app.route('/manager/view_report/<int:req_id>')
@login_required
def manager_view_report(req_id):
    req = AnalysisRequest.query.get_or_404(req_id)
    if req.manager_username != current_user.username:
        flash('غير مصرح')
        return redirect(url_for('manager_requests'))
    if req.status != 'completed':
        flash('التقرير لم يكتمل بعد')
        return redirect(url_for('manager_requests'))
    if not req.is_read:
        req.is_read = True
        db.session.commit()
    return render_template('manager_report.html', req=req)

# Admin: list all requests
@app.route('/admin/requests')
@login_required
def admin_requests():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    all_requests = AnalysisRequest.query.order_by(AnalysisRequest.created_at.desc()).all()
    pending_count = AnalysisRequest.query.filter_by(status='pending').count()
    return render_template('admin_requests.html', requests=all_requests, pending_count=pending_count)

# Admin: analyze a request
@app.route('/admin/analyze/<int:req_id>', methods=['POST'])
@login_required
def admin_analyze(req_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    req = AnalysisRequest.query.get_or_404(req_id)
    if req.status != 'pending':
        flash('هذا الطلب تم تحليله بالفعل')
        return redirect(url_for('admin_requests'))
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], req.stored_filename)
    if not os.path.exists(filepath):
        flash('الملف غير موجود')
        return redirect(url_for('admin_requests'))
    # Update status to analyzing
    req.status = 'analyzing'
    db.session.commit()
    # Perform analysis
    report_data = analyze_uploaded_file(filepath, req.id)
    if report_data is None:
        req.status = 'pending'
        db.session.commit()
        flash('فشل في تحليل الملف')
        return redirect(url_for('admin_requests'))
    # Save report
    req.status = 'completed'
    req.report_data = report_data
    req.report_generated_at = datetime.utcnow()
    req.report_summary = f"إجمالي السطور: {report_data['total_lines']} | نجاح: {report_data['success']} | فشل: {report_data['failed']} | تنبيهات: {len(report_data['alerts'])}"
    db.session.commit()
    flash('تم تحليل الملف وإنشاء التقرير بنجاح')
    return redirect(url_for('admin_requests'))

# Admin user management (already partially added, ensure routes exist)
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

# ---------- Report page (simple stats for all users) ----------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    report_data = None
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
    from sqlalchemy import func
    top_ips = db.session.query(Log.src_ip, func.count(Log.id)).group_by(Log.src_ip).order_by(func.count(Log.id).desc()).limit(5).all()
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
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_RIGHT, TA_CENTER, TA_LEFT
from io import BytesIO
from flask import make_response
from sqlalchemy import func   # <-- Import at the top
from collections import Counter

@app.route('/report/pdf')
@login_required
def report_pdf():
    # ---- Collect detailed data ----
    total_logs = Log.query.count()
    total_alerts = Alert.query.count()
    success_count = Log.query.filter_by(status='success').count()
    failed_count = Log.query.filter_by(status='failed').count()

    # Event type breakdown
    event_types = db.session.query(Log.event_type, func.count(Log.id)).group_by(Log.event_type).all()
    event_type_data = [["Event Type", "Count"]] + [[et, str(cnt)] for et, cnt in event_types]

    # Alert severity distribution
    severity_counts = db.session.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_data = [["Severity", "Count"]] + [[sev, str(cnt)] for sev, cnt in severity_counts]

    # Top 5 IPs with failed logins (if any)
    failed_logins = db.session.query(Log.src_ip, func.count(Log.id)).filter(
        Log.event_type == 'login', Log.status == 'failed'
    ).group_by(Log.src_ip).order_by(func.count(Log.id).desc()).limit(5).all()
    top_failed_ips = [["IP", "Failed Attempts"]] + [[ip, str(cnt)] for ip, cnt in failed_logins] if failed_logins else [["No failed logins found", ""]]

    # Top 5 IPs overall
    top_ips_all = db.session.query(Log.src_ip, func.count(Log.id)).group_by(Log.src_ip).order_by(func.count(Log.id).desc()).limit(5).all()
    top_ips_data = [["IP", "Total Logs"]] + [[ip, str(cnt)] for ip, cnt in top_ips_all]

    # Recent alerts (last 5)
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    recent_alerts_data = [["Timestamp", "Severity", "Rule", "Description"]]
    for a in recent_alerts:
        recent_alerts_data.append([
            a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            a.severity,
            a.rule_name,
            a.description[:80] + ("..." if len(a.description) > 80 else "")
        ])

    # General stats
    success_rate = (success_count / total_logs * 100) if total_logs else 0
    stats_data = [
        ["Total Logs", str(total_logs)],
        ["Total Alerts", str(total_alerts)],
        ["Success Count", str(success_count)],
        ["Failed Count", str(failed_count)],
        ["Success Rate", f"{success_rate:.1f}%"],
    ]

    # ---- PDF Generation ----
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)

    # Font setup
    try:
        pdfmetrics.registerFont(TTFont('Arial', 'C:/Windows/Fonts/arial.ttf'))
        font_name = 'Arial'
    except:
        font_name = 'Helvetica'

    styles = getSampleStyleSheet()
    style_normal = ParagraphStyle('Normal', parent=styles['Normal'], alignment=TA_LEFT, fontName=font_name, fontSize=10)
    style_header = ParagraphStyle('Header', parent=styles['Heading2'], alignment=TA_LEFT, fontName=font_name, fontSize=12, textColor=colors.HexColor('#0f6bff'))
    style_title = ParagraphStyle('Title', parent=styles['Title'], alignment=TA_CENTER, fontName=font_name, fontSize=16)

    elements = []

    # Title and metadata
    elements.append(Paragraph("SIEM Security Report", style_title))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", style_normal))
    elements.append(Paragraph(f"User: {current_user.username} (Role: {current_user.role})", style_normal))
    if current_user.role == 'manager':
        elements.append(Paragraph("Note: You can request a deeper analysis by submitting a log file to the admin.", style_normal))
    elements.append(Spacer(1, 12))

    # General Statistics
    elements.append(Paragraph("1. Overall Statistics", style_header))
    stats_table = Table(stats_data, colWidths=[120, 80])
    stats_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 12))

    # Event Type Breakdown
    elements.append(Paragraph("2. Events by Type", style_header))
    event_table = Table(event_type_data, colWidths=[120, 80])
    event_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (-1,0), colors.lightblue),
    ]))
    elements.append(event_table)
    elements.append(Spacer(1, 12))

    # Alert Severity Distribution
    elements.append(Paragraph("3. Alert Severity Distribution", style_header))
    severity_table = Table(severity_data, colWidths=[120, 80])
    severity_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (-1,0), colors.lightcoral),
    ]))
    elements.append(severity_table)
    elements.append(Spacer(1, 12))

    # Top IPs Overall
    elements.append(Paragraph("4. Top 5 Source IPs (All Events)", style_header))
    top_ips_table = Table(top_ips_data, colWidths=[120, 80])
    top_ips_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (-1,0), colors.lightyellow),
    ]))
    elements.append(top_ips_table)
    elements.append(Spacer(1, 12))

    # Top Failed Login IPs
    elements.append(Paragraph("5. Top 5 IPs with Failed Logins", style_header))
    failed_ips_table = Table(top_failed_ips, colWidths=[120, 80])
    failed_ips_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (-1,0), colors.lightyellow),
    ]))
    elements.append(failed_ips_table)
    elements.append(Spacer(1, 12))

    # Recent Alerts
    elements.append(Paragraph("6. Recent Alerts (Last 5)", style_header))
    alert_table = Table(recent_alerts_data, colWidths=[80, 50, 70, 110])
    alert_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (-1,0), colors.lightgreen),
    ]))
    elements.append(alert_table)
    elements.append(Spacer(1, 12))

    # Recommendations
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

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("This report was generated automatically by the SIEM system.", style_normal))

    # Build PDF
    doc.build(elements)
    pdf_data = buffer.getvalue()
    buffer.close()

    response = make_response(pdf_data)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=siem_report.pdf'
    return response
# ---------- Sniffer & Agent loops (original) ----------
def packet_callback(packet):
    with app.app_context():
        from scapy.all import IP, TCP, UDP, ICMP, Raw
        try:
            src_ip = None
            dst_ip = None
            protocol = "Other"
            details = ""
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
                    details = f"Sport: {src_port} Dport: {dst_port}"
                    if Raw in packet:
                        payload = packet[Raw].load[:100]
                        if b"GET" in payload or b"POST" in payload:
                            details += f" Payload: {payload}"
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    details = f"Sport: {src_port} Dport: {dst_port}"
                elif ICMP in packet:
                    protocol = "ICMP"
                    details = f"Type: {packet[ICMP].type}"
                else:
                    protocol = f"IP-{packet[IP].proto}"
            else:
                details = packet.summary()[:100]

            if not src_ip:
                src_ip = "0.0.0.0"

            log = Log(
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                username=None,
                event_type="network_packet",
                status="captured",
                details=f"Proto: {protocol} | {details}",
                request_path=dst_ip if dst_ip else "",
                method=protocol,
                user_agent=None
            )
            db.session.add(log)
            db.session.commit()
            if src_ip != "0.0.0.0":
                update_device(src_ip)
            if dst_ip and dst_ip != src_ip:
                update_device(dst_ip)

            socketio.emit('new_packet', {
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'protocol': protocol,
                'details': details[:100]
            })

            key = (src_ip, dst_ip, src_port, dst_port, protocol)
            with temp_lock:
                conn = temp_connections[key]
                conn['packets'] += 1
                conn['bytes'] += size
                conn['last_seen'] = datetime.utcnow()
        except Exception as e:
            print(f"خطأ في معالجة الحزمة: {e}")

def sniff_loop(interface=None):
    from scapy.all import sniff
    global sniffer_active
    sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda x: not sniffer_active)

def agent_send_connections():
    global agent_active
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
                        timestamp=data['last_seen'] or datetime.utcnow(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        packets_count=data['packets'],
                        bytes_total=data['bytes'],
                        is_active=False,
                        agent_id='main_agent'
                    )
                    db.session.add(conn)
                db.session.commit()
            except Exception as e:
                print("خطأ في حفظ الاتصالات:", e)

def advanced_threat_analysis():
    while True:
        time.sleep(300)
        with app.app_context():
            try:
                cutoff = datetime.utcnow() - timedelta(minutes=5)
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
                            NetworkAlert.timestamp >= datetime.utcnow() - timedelta(hours=1)
                        ).first()
                        if not existing:
                            alert = NetworkAlert(
                                severity='High',
                                alert_type='port_scan',
                                src_ip=ip,
                                description=f'Port scan detected from {ip} targeting {len(ports)} distinct ports in 5 minutes',
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
                            NetworkAlert.timestamp >= datetime.utcnow() - timedelta(hours=1)
                        ).first()
                        if not existing:
                            alert = NetworkAlert(
                                severity='Medium',
                                alert_type='excessive_connections',
                                src_ip=ip,
                                description=f'Excessive connections ({count}) from {ip} in 5 minutes'
                            )
                            db.session.add(alert)
                db.session.commit()
            except Exception as e:
                print("خطأ في تحليل التهديدات:", e)

# ---------- Run the application ----------
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)