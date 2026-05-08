# init_db.py
from app import app, db
from models import (
    User, Policy, ComplianceRequirement,
    Risk, Incident, CriticalSystem
)
from datetime import datetime, timedelta

# -----------------------------
# Helpers
# -----------------------------
def policy_exists(title):
    return Policy.query.filter_by(title=title).first() is not None

def risk_exists(title):
    return Risk.query.filter_by(title=title).first() is not None

def incident_exists(title):
    return Incident.query.filter_by(title=title).first() is not None

def compliance_exists(standard, req_id):
    return ComplianceRequirement.query.filter_by(
        standard=standard, req_id=req_id
    ).first() is not None

def system_exists(name):
    return CriticalSystem.query.filter_by(name=name).first() is not None


# -----------------------------
# Admin user
# -----------------------------
def create_admin():
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(username="admin", role="admin", accepted_policies=True)
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        print("✔ Admin created")
    return admin


# -----------------------------
# Policies
# -----------------------------
def add_policies(admin):
    policies = [
        ("Security Policy", "Cybersecurity", "Main security rules"),
        ("Access Control Policy", "Cybersecurity", "Access management rules"),
        ("Incident Response Policy", "Operational", "Incident handling process"),
    ]

    for title, ptype, summary in policies:
        if not policy_exists(title):
            db.session.add(Policy(
                title=title,
                policy_type=ptype,
                version="1.0",
                summary=summary,
                full_content=summary,
                approved_by="CISO",
                status="Active",
                last_reviewed=datetime.utcnow(),
                next_review=datetime.utcnow() + timedelta(days=365),
                created_by_id=admin.id,
                last_updated_by_id=admin.id
            ))
            print(f"✔ Policy added: {title}")

    db.session.commit()


# -----------------------------
# Risks
# -----------------------------
def add_risks():
    risks = [
        ("Weak passwords", "Security risk", 4, 5),
        ("No backup", "Operational risk", 3, 5),
    ]

    for title, desc, lik, imp in risks:
        if not risk_exists(title):
            db.session.add(Risk(
                title=title,
                description=desc,
                category="Security",
                likelihood=lik,
                impact=imp,
                risk_score=lik * imp,
                risk_response="Mitigate",
                owner="IT",
                status="Open"
            ))
            print(f"✔ Risk added: {title}")

    db.session.commit()


# -----------------------------
# Incidents
# -----------------------------
def add_incidents():
    incidents = [
        ("Phishing attack", "High"),
        ("DDoS attack", "Medium"),
    ]

    for title, severity in incidents:
        if not incident_exists(title):
            db.session.add(Incident(
                title=title,
                severity=severity,
                description="Auto generated incident",
                detection_time=datetime.utcnow(),
                assignee="SOC Team",
                status="Open"
            ))
            print(f"✔ Incident added: {title}")

    db.session.commit()


# -----------------------------
# Compliance
# -----------------------------
def add_compliance():
    data = [
        ("ISO 27001", "A.9.1.2", "Access control required"),
        ("PCI DSS", "10.2.1", "Log access required"),
    ]

    for std, req, desc in data:
        if not compliance_exists(std, req):
            db.session.add(ComplianceRequirement(
                standard=std,
                req_id=req,
                description=desc,
                current_status="Partial",
                evidence="N/A",
                remediation_plan="Improve controls",
                target_completion=datetime.utcnow() + timedelta(days=90)
            ))
            print(f"✔ Compliance added: {std} - {req}")

    db.session.commit()


# -----------------------------
# Critical Systems
# -----------------------------
def add_systems():
    systems = [
        ("Email System", "Critical communication", 240, 60),
        ("CRM Database", "Customer data", 120, 30),
    ]

    for name, desc, rto, rpo in systems:
        if not system_exists(name):
            db.session.add(CriticalSystem(
                name=name,
                description=desc,
                rto=rto,
                rpo=rpo,
                backup_frequency="Daily",
                owner="IT"
            ))
            print(f"✔ System added: {name}")

    db.session.commit()


# -----------------------------
# Main
# -----------------------------
def main():
    with app.app_context():
        print("🚀 Initializing DB...")

        db.create_all()

        admin = create_admin()
        add_policies(admin)
        add_risks()
        add_incidents()
        add_compliance()
        add_systems()

        print("\n🎉 DONE!")
        print("Admin login: admin / admin123")


if __name__ == "__main__":
    main()