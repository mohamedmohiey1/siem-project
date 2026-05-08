# SIEM-SOC | GRC Enterprise Platform

Enterprise-grade SIEM and GRC platform built using Flask, SQLite, and Scapy for real-time monitoring, risk management, compliance tracking, and incident response.

---

# Overview

SIEM-SOC | GRC Platform is a cybersecurity monitoring and governance solution developed as a Graduation Project.

The platform combines multiple cybersecurity and governance modules into one integrated system, including:

- Security Information and Event Management (SIEM)
- Governance, Risk, and Compliance (GRC)
- Real-time packet sniffing
- Security alert monitoring
- Risk analysis and heatmaps
- Compliance tracking
- Incident management
- Business continuity planning
- Security reporting and analytics

The system is designed to simulate a professional Security Operations Center (SOC) environment with a modern and responsive interface.

---

# Features

## SIEM Features

- Real-time security log monitoring
- Alert generation and threat detection
- Packet sniffing using Scapy
- Device and activity monitoring
- Security reports and analytics
- Dashboard with attack indicators
- Threat activity tracking

## GRC Features

- Risk Register Management
- Compliance Tracking
- Policy Management
- Incident Management
- Business Continuity Planning (BCP)
- KPI Dashboard
- Risk Heatmaps
- Governance Reporting

## Access Control

- Admin dashboard
- Manager dashboard
- Role-based access control
- User management system

---

# Technologies Used

| Category | Technologies |
|----------|--------------|
| Backend | Python, Flask |
| Database | SQLite |
| Frontend | HTML5, CSS3, JavaScript |
| Security Tools | Scapy |
| Templates | Jinja2 |

---

# System Architecture

The platform consists of:

- Flask web application for backend processing
- SQLite database for storing logs, alerts, users, and risk data
- Scapy integration for packet sniffing and network monitoring
- HTML/CSS/JavaScript frontend for dashboard visualization
- GRC modules for governance and compliance management

---
###Create Virtual Environment

python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python init_db.py
python app.py
http://127.0.0.1:5000

| Module              | Description                    |
| ------------------- | ------------------------------ |
| SIEM Dashboard      | Real-time monitoring dashboard |
| Packet Sniffer      | Live network packet capture    |
| Risk Register       | Risk analysis and scoring      |
| Compliance          | Compliance framework tracking  |
| Incident Management | Security incident handling     |
| Policies            | Security policy management     |
| KPI Dashboard       | Security metrics and KPIs      |
| Heatmap             | Visual risk visualization      |


Security Features
Role-based authentication
Secure session management
Risk scoring system
Threat monitoring
Real-time alerts
Log analysis
Incident response workflow
Future Improvements
Elasticsearch integration
Docker deployment
Real-time WebSocket updates
AI-powered threat detection
REST API integration
Cloud deployment
Multi-tenant architecture
Advanced reporting engine
Developer

Mohamed Mohiey

Cyber Security and SIEM Developer

License

This project was developed for educational and graduation project purposes.

# Installation

## Clone Repository

```bash
git clone https://github.com/mohamedmohiey1/siem-project.git
cd siem-project
