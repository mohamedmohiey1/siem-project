from collections import defaultdict
from datetime import datetime, timedelta
from models import db, Log, Alert
from threat_intel import BLACKLIST_IPS

# Tracking structures
failed_attempts = defaultdict(list)      # for brute force
http_errors = defaultdict(list)          # for excessive 404/500
sensitive_paths = ['/admin', '/config', '/.env', '/backup', '/wp-admin']

def apply_detection_rules(log_obj):
    alerts = []

    # ------------------- CRITICAL SEVERITY -------------------
    # 1. Blacklisted IP (Critical)
    if log_obj.src_ip in BLACKLIST_IPS:
        alerts.append(Alert(
            severity='Critical',
            rule_name='Blacklisted IP',
            description=f'Activity from blacklisted IP {log_obj.src_ip}',
            src_ip=log_obj.src_ip,
            log_ids=str(log_obj.id)
        ))

    # ------------------- HIGH SEVERITY -------------------
    # 2. Brute Force (High)
    if log_obj.event_type == 'login' and log_obj.status == 'failed':
        ip = log_obj.src_ip
        now = datetime.utcnow()
        failed_attempts[ip].append(now)
        failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < timedelta(seconds=60)]
        if len(failed_attempts[ip]) >= 5:
            alerts.append(Alert(
                severity='High',
                rule_name='Brute Force Detection',
                description=f'5+ failed logins from {ip} in 60s',
                src_ip=ip,
                log_ids=str(log_obj.id)
            ))

    # 3. Access to sensitive path (High)
    if log_obj.event_type == 'web_request' and log_obj.request_path:
        path = log_obj.request_path.lower()
        if any(sensitive in path for sensitive in sensitive_paths):
            alerts.append(Alert(
                severity='High',
                rule_name='Sensitive Path Access',
                description=f'Sensitive path accessed: {log_obj.request_path} from {log_obj.src_ip}',
                src_ip=log_obj.src_ip,
                log_ids=str(log_obj.id)
            ))

    # ------------------- MEDIUM SEVERITY -------------------
    # 4. Excessive HTTP errors (Medium)
    if log_obj.event_type == 'web_request' and log_obj.status == 'failed':
        ip = log_obj.src_ip
        key = (ip, 'http_error')
        now = datetime.utcnow()
        http_errors[key].append(now)
        http_errors[key] = [t for t in http_errors[key] if now - t < timedelta(minutes=1)]
        if len(http_errors[key]) >= 10:
            alerts.append(Alert(
                severity='Medium',
                rule_name='Excessive HTTP Errors',
                description=f'10+ HTTP errors (4xx/5xx) from {ip} in 1 minute',
                src_ip=ip,
                log_ids=str(log_obj.id)
            ))
            # Clear to avoid duplicate alerts
            http_errors[key] = []

    # 5. Unusual event volume from single IP (Medium)
    # Track events per IP per minute
    if not hasattr(apply_detection_rules, 'ip_event_count'):
        apply_detection_rules.ip_event_count = defaultdict(list)
    ip = log_obj.src_ip
    now = datetime.utcnow()
    apply_detection_rules.ip_event_count[ip].append(now)
    apply_detection_rules.ip_event_count[ip] = [t for t in apply_detection_rules.ip_event_count[ip] if now - t < timedelta(minutes=1)]
    if len(apply_detection_rules.ip_event_count[ip]) > 50:
        alerts.append(Alert(
            severity='Medium',
            rule_name='High Event Rate',
            description=f'More than 50 events from {ip} in 1 minute',
            src_ip=ip,
            log_ids=str(log_obj.id)
        ))
        apply_detection_rules.ip_event_count[ip] = []  # reset after alert

    # ------------------- LOW SEVERITY -------------------
    # 6. Single failed login (Low) – informational
    if log_obj.event_type == 'login' and log_obj.status == 'failed':
        # Only alert for first failed login from this IP (to avoid spam)
        key = (log_obj.src_ip, 'first_fail')
        if not hasattr(apply_detection_rules, 'first_fail_seen'):
            apply_detection_rules.first_fail_seen = set()
        if key not in apply_detection_rules.first_fail_seen:
            apply_detection_rules.first_fail_seen.add(key)
            alerts.append(Alert(
                severity='Low',
                rule_name='Failed Login Attempt',
                description=f'Failed login attempt from {log_obj.src_ip}',
                src_ip=log_obj.src_ip,
                log_ids=str(log_obj.id)
            ))

    # 7. Unusual user agent (Low) – optional
    if log_obj.user_agent and ('bot' in log_obj.user_agent.lower() or 'scanner' in log_obj.user_agent.lower()):
        alerts.append(Alert(
            severity='Low',
            rule_name='Suspicious User Agent',
            description=f'Request from {log_obj.src_ip} with suspicious UA: {log_obj.user_agent[:50]}',
            src_ip=log_obj.src_ip,
            log_ids=str(log_obj.id)
        ))

    return alerts