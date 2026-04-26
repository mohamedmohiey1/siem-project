from collections import defaultdict
from datetime import datetime, timedelta
from models import db, Log, Alert
from threat_intel import BLACKLIST_IPS

failed_attempts = defaultdict(list)

def apply_detection_rules(log_obj):
    alerts = []
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
    if log_obj.src_ip in BLACKLIST_IPS:
        alerts.append(Alert(
            severity='Critical',
            rule_name='Blacklisted IP',
            description=f'Activity from blacklisted IP {log_obj.src_ip}',
            src_ip=log_obj.src_ip,
            log_ids=str(log_obj.id)
        ))
    return alerts