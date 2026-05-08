from collections import defaultdict
from datetime import datetime, timedelta
from models import db, Log, Alert, Risk
from threat_intel import BLACKLIST_IPS

# Tracking structures
failed_attempts = defaultdict(list)
http_errors = defaultdict(list)
sensitive_paths = ['/admin', '/config', '/.env', '/backup', '/wp-admin']

# لتجنب تكرار المخاطر لنفس القاعدة ونفس IP خلال 24 ساعة
_recent_risks = {}

def create_risk_for_alert(alert, event_time):
    """إنشاء Risk مرتبط بالتنبيه إذا كان severity High أو Critical."""
    if alert.severity not in ('High', 'Critical'):
        return None

    key = f"{alert.rule_name}_{alert.src_ip}"
    now = event_time if event_time else datetime.utcnow()
    
    # منع التكرار خلال 24 ساعة
    if key in _recent_risks and (now - _recent_risks[key]) < timedelta(hours=24):
        print(f"⏩ Risk already created recently for {key}")
        return None

    # حساب likelihood و impact
    if alert.severity == 'Critical':
        likelihood, impact = 5, 5
    else:  # High
        likelihood, impact = 4, 4

    try:
        # التحقق إذا كان هناك Risk مفتوح لنفس القاعدة و IP
        existing_risk = Risk.query.filter_by(
            title=f"{alert.rule_name} from {alert.src_ip}",
            status='Open'
        ).first()
        if existing_risk:
            alert.risk_id = existing_risk.id
            db.session.add(alert)
            print(f"🔗 Linked alert {alert.id} to existing risk {existing_risk.id}")
            return existing_risk

        # إنشاء Risk جديد
        risk = Risk(
            title=f"{alert.rule_name} from {alert.src_ip}",
            description=f"Auto-generated from alert: {alert.description}",
            category="Technical",
            likelihood=likelihood,
            impact=impact,
            risk_score=likelihood * impact,
            risk_response="Mitigate",
            owner="System",
            status="Open"
        )
        db.session.add(risk)
        db.session.flush()   # لكي نحصل على risk.id
        alert.risk_id = risk.id
        db.session.add(alert)
        _recent_risks[key] = now
        print(f"✅ New risk created: {risk.title} (ID={risk.id}) and linked to alert {alert.id}")
        return risk
    except Exception as e:
        print(f"❌ Failed to create risk for alert {alert.id}: {e}")
        db.session.rollback()
        return None

def apply_detection_rules(log_obj):
    """
    تطبيق قواعد الكشف على سجل واحد.
    يستخدم log_obj.timestamp (وقت الحدث الفعلي) بدلاً من وقت المعالجة.
    """
    alerts = []
    
    # الوقت الحقيقي للحدث (من السجل نفسه)
    event_time = log_obj.timestamp if log_obj.timestamp else datetime.utcnow()

    # --- Critical: Blacklisted IP ---
    if log_obj.src_ip in BLACKLIST_IPS:
        alert = Alert(
            severity='Critical',
            rule_name='Blacklisted IP',
            description=f'Activity from blacklisted IP {log_obj.src_ip}',
            src_ip=log_obj.src_ip,
            log_ids=str(log_obj.id)
        )
        alerts.append(alert)
        create_risk_for_alert(alert, event_time)

    # --- High: Brute Force (5 failed logins in 60 seconds) ---
    if log_obj.event_type == 'login' and log_obj.status == 'failed':
        ip = log_obj.src_ip
        failed_attempts[ip].append(event_time)
        # احتفظ فقط بالمحاولات خلال آخر 60 ثانية حسب الطوابع الزمنية للسجلات
        failed_attempts[ip] = [t for t in failed_attempts[ip] if (event_time - t).total_seconds() <= 60]
        if len(failed_attempts[ip]) >= 5:
            alert = Alert(
                severity='High',
                rule_name='Brute Force Detection',
                description=f'5+ failed logins from {ip} in 60s',
                src_ip=ip,
                log_ids=str(log_obj.id)
            )
            alerts.append(alert)
            create_risk_for_alert(alert, event_time)

    # --- High: Sensitive Path Access ---
    if log_obj.event_type == 'web_request' and log_obj.request_path:
        path = log_obj.request_path.lower()
        if any(s in path for s in sensitive_paths):
            alert = Alert(
                severity='High',
                rule_name='Sensitive Path Access',
                description=f'Sensitive path accessed: {log_obj.request_path} from {log_obj.src_ip}',
                src_ip=log_obj.src_ip,
                log_ids=str(log_obj.id)
            )
            alerts.append(alert)
            create_risk_for_alert(alert, event_time)

    # --- Medium: Excessive HTTP Errors (10+ errors in 1 minute) ---
    if log_obj.event_type == 'web_request' and log_obj.status == 'failed':
        ip = log_obj.src_ip
        key = (ip, 'http_error')
        http_errors[key].append(event_time)
        http_errors[key] = [t for t in http_errors[key] if (event_time - t).total_seconds() <= 60]
        if len(http_errors[key]) >= 10:
            alert = Alert(
                severity='Medium',
                rule_name='Excessive HTTP Errors',
                description=f'10+ HTTP errors from {ip} in 1 minute',
                src_ip=ip,
                log_ids=str(log_obj.id)
            )
            alerts.append(alert)
            # لا ننشئ Risk للـ Medium (يمكن تغييره حسب الحاجة)
            http_errors[key] = []

    # --- Medium: High Event Rate (50+ events in 1 minute) ---
    if not hasattr(apply_detection_rules, 'ip_event_count'):
        apply_detection_rules.ip_event_count = defaultdict(list)
    ip = log_obj.src_ip
    apply_detection_rules.ip_event_count[ip].append(event_time)
    apply_detection_rules.ip_event_count[ip] = [
        t for t in apply_detection_rules.ip_event_count[ip] 
        if (event_time - t).total_seconds() <= 60
    ]
    if len(apply_detection_rules.ip_event_count[ip]) > 50:
        alert = Alert(
            severity='Medium',
            rule_name='High Event Rate',
            description=f'More than 50 events from {ip} in 1 minute',
            src_ip=ip,
            log_ids=str(log_obj.id)
        )
        alerts.append(alert)
        apply_detection_rules.ip_event_count[ip] = []

    # --- Low: First Failed Login ---
    if log_obj.event_type == 'login' and log_obj.status == 'failed':
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

    # --- Low: Suspicious User Agent ---
    if log_obj.user_agent and ('bot' in log_obj.user_agent.lower() or 'scanner' in log_obj.user_agent.lower()):
        alerts.append(Alert(
            severity='Low',
            rule_name='Suspicious User Agent',
            description=f'Suspicious UA: {log_obj.user_agent[:50]} from {log_obj.src_ip}',
            src_ip=log_obj.src_ip,
            log_ids=str(log_obj.id)
        ))

    return alerts