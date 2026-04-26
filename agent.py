import time
import threading
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime

API_URL = "http://localhost:5000/api/agent/connections"   # غيّر العنوان حسب جهاز الـ Dashboard
AGENT_ID = "agent_main"

connections = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': None, 'src_port': None, 'dst_port': None})
lock = threading.Lock()

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "IP"
        src_port = None
        dst_port = None
        size = len(packet)
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
        else:
            protocol = f"Other-{packet[IP].proto}"
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        with lock:
            conn = connections[key]
            conn['packets'] += 1
            conn['bytes'] += size
            conn['last_seen'] = datetime.utcnow()
            if src_port is not None:
                conn['src_port'] = src_port
            if dst_port is not None:
                conn['dst_port'] = dst_port

def send_connections():
    global connections
    with lock:
        to_send = []
        for (src_ip, dst_ip, src_port, dst_port, proto), data in connections.items():
            to_send.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': data['src_port'],
                'dst_port': data['dst_port'],
                'protocol': proto,
                'packets': data['packets'],
                'bytes': data['bytes'],
                'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
            })
        connections = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': None, 'src_port': None, 'dst_port': None})
    if to_send:
        try:
            resp = requests.post(API_URL, json={'agent_id': AGENT_ID, 'connections': to_send}, timeout=5)
            if resp.status_code != 200:
                print("فشل الإرسال:", resp.text)
        except Exception as e:
            print("خطأ في الاتصال:", e)

def start_sniffing():
    print("بدء التقاط الحزم في Agent... (يتطلب صلاحيات مرتفعة)")
    sniff(prn=packet_handler, store=False)

if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    while True:
        time.sleep(30)
        send_connections()