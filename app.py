from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
import os
import re
import sqlite3
import subprocess
import platform
import threading
import time
from collections import defaultdict
from werkzeug.utils import secure_filename
from models import db, Log, Alert, Device, UserActivity, NetworkConnection, NetworkAlert
from rules import apply_detection_rules

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///siem.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = './uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# متغيرات السنايفر
sniffer_active = False
sniffer_thread = None
sniffer_interface = None

# متغيرات الـ Agent الداخلي (جمع الاتصالات)
agent_active = False
temp_connections = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': None})
temp_lock = threading.Lock()

# ------------------- ترقية قاعدة البيانات -------------------
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
        print("ترقية قاعدة البيانات:", e)

with app.app_context():
    db.create_all()
    upgrade_database_safe()

# ------------------- دوال تحليل السجلات -------------------
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

# ------------------- Sniffer (التقاط الحزم مع WebSocket) -------------------
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

            # حفظ في جدول Logs للتوثيق العام
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

            # تجميع إحصائيات الاتصالات لجدول NetworkConnection
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

@app.route('/start_sniffer', methods=['POST'])
def start_sniffer():
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
def stop_sniffer():
    global sniffer_active
    sniffer_active = False
    return jsonify({'status': 'Sniffer stopped'})

@app.route('/sniffer_status')
def sniffer_status():
    return jsonify({'active': sniffer_active, 'interface': sniffer_interface})

@app.route('/sniffer')
def sniffer_page():
    return render_template('sniffer.html')

# ------------------- Agent داخلي (حفظ الاتصالات في قاعدة البيانات) -------------------
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

# ------------------- تحليل التهديدات المتقدم -------------------
def advanced_threat_analysis():
    while True:
        time.sleep(300)  # 5 دقائق
        with app.app_context():
            try:
                cutoff = datetime.utcnow() - timedelta(minutes=5)
                # 1. Port Scan
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
                # 2. Excessive Connections
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

# ------------------- Routes لبدء وإيقاف الـ Agent -------------------
@app.route('/start_agent', methods=['POST'])
def start_agent():
    global agent_active
    if agent_active:
        return jsonify({'status': 'Agent already running'}), 400
    agent_active = True
    threading.Thread(target=agent_send_connections, daemon=True).start()
    threading.Thread(target=advanced_threat_analysis, daemon=True).start()
    return jsonify({'status': 'Agent started'})

@app.route('/stop_agent', methods=['POST'])
def stop_agent():
    global agent_active
    agent_active = False
    return jsonify({'status': 'Agent stopped'})

@app.route('/agent_status')
def agent_status():
    global agent_active
    return jsonify({'active': agent_active})

# ------------------- API للـ Agent الخارجي -------------------
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

# ------------------- صفحات العرض المتقدمة -------------------
@app.route('/network_connections')
def network_connections():
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
def network_alerts():
    alerts = NetworkAlert.query.order_by(NetworkAlert.timestamp.desc()).all()
    return render_template('network_alerts.html', alerts=alerts)

# ------------------- الاكتشاف وجدار الحماية -------------------
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
def network_devices():
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

# ------------------- المسارات الأساسية -------------------
@app.route('/')
def dashboard():
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
def view_logs():
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
def view_alerts():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    alerts = query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('alerts.html', alerts=alerts, selected_severity=severity)

@app.route('/submit_log', methods=['GET','POST'])
def submit_log_form():
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
def upload_logs():
    stats = None
    if request.method == 'POST':
        file = request.files.get('file')
        if file and '.' in file.filename and file.filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS:
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
def devices():
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
def device_details(ip):
    logs = Log.query.filter_by(src_ip=ip).order_by(Log.timestamp.desc()).limit(200).all()
    alerts = Alert.query.filter_by(src_ip=ip).order_by(Alert.timestamp.desc()).all()
    device = Device.query.filter_by(ip=ip).first()
    return render_template('device_details.html', ip=ip, device=device, logs=logs, alerts=alerts)

# ------------------- تشغيل التطبيق -------------------
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)