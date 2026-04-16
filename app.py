from flask import Flask, render_template, request, session, jsonify, redirect, url_for
from flask_mail import Mail, Message
import random
import json
import requests
from bs4 import BeautifulSoup
import os
import platform
import socket
import psutil
import ssl
import datetime

from Database import db, init_db, Signup, WebScan, NetworkScan, SystemScan

app = Flask(__name__)
app.secret_key = "darkblend_secret_key_2025"

# ---------------- DATABASE ---------------- #
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql+psycopg2://postgres:12345@127.0.0.1:5432/sign_up"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
init_db(app)

# ---------------- EMAIL CONFIG ---------------- #
try:
    with open('config.json', 'r') as f:
        params = json.load(f).get('param', {})
except:
    params = {}

app.config.update({
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USERNAME': params.get('gmail-user', ''),
    'MAIL_PASSWORD': params.get('gmail-password', ''),
    'MAIL_USE_TLS': True,
    'MAIL_DEFAULT_SENDER': params.get('gmail-user', '')
})

mail = Mail(app)

# ─────────────────────────────────────────────────────────
#  PAGE ROUTES
# ─────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('home.html', user=session.get('email'))

@app.route('/features')
def features():
    return render_template('features.html', user=session.get('email'))

@app.route('/signup')
def signup():
    if 'email' in session:
        return redirect(url_for('scanner'))
    return render_template('signup.html')

@app.route('/scanner')
def scanner():
    if 'email' not in session:
        return redirect(url_for('signup'))
    return render_template('scanner.html', user=session.get('email'))

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('signup'))
    email = session['email']
    web_scans    = WebScan.query.filter_by(email=email).order_by(WebScan.timestamp.desc()).all()
    net_scans    = NetworkScan.query.filter_by(email=email).order_by(NetworkScan.timestamp.desc()).all()
    sys_scans    = SystemScan.query.filter_by(email=email).order_by(SystemScan.timestamp.desc()).all()
    return render_template('dashboard.html',
        user=email,
        web_scans=web_scans,
        net_scans=net_scans,
        sys_scans=sys_scans,
        web_count=len(web_scans),
        net_count=len(net_scans),
        sys_count=len(sys_scans)
    )
 
@app.route('/solutions')
def solutions():
    if 'email' not in session:
        return redirect(url_for('signup'))
    return render_template('solutions.html', user=session.get('email'))
# ─────────────────────────────────────────────────────────
#  OTP AUTH
# ─────────────────────────────────────────────────────────

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email') or request.json.get('email') if request.is_json else request.form.get('email')
    if not email:
        return jsonify({"message": "Enter valid email", "status": "error"})

    otp = str(random.randint(100000, 999999))
    session['otp'] = otp
    session['email'] = email
    session['otp_attempts'] = 5

    user = Signup.query.filter_by(gmail=email).first()
    if user:
        user.otp = otp
    else:
        user = Signup(gmail=email, otp=otp)
        db.session.add(user)
    db.session.commit()

    try:
        msg = Message('DarkBlend — Your OTP Code', recipients=[email])
        msg.html = f"""
        <div style="font-family:monospace;background:#070b12;color:#00f5c8;padding:32px;border-radius:12px;max-width:480px;">
          <h2 style="color:#00f5c8;margin-bottom:8px;">DarkBlend Access Code</h2>
          <p style="color:#6b8caa;margin-bottom:24px;">Your one-time verification code:</p>
          <div style="background:#0d1220;border:1px solid #00f5c8;border-radius:8px;padding:20px;text-align:center;font-size:36px;letter-spacing:8px;font-weight:900;">{otp}</div>
          <p style="color:#2a3f55;margin-top:20px;font-size:11px;">Expires in 60 seconds. Do not share this code.</p>
        </div>
        """
        mail.send(msg)
        return jsonify({"message": "OTP Sent", "status": "success"})
    except Exception as e:
        return jsonify({"message": str(e), "status": "error"})

@app.route('/validate', methods=['POST'])
def validate():
    email = session.get('email')
    entered_otp = request.form.get('otp')
    attempts = session.get('otp_attempts', 5)

    if not entered_otp:
        return jsonify({"message": "Enter OTP", "status": "error"})

    if attempts <= 0:
        return jsonify({"message": "Max attempts reached. Request new OTP.", "status": "error"})

    user = Signup.query.filter_by(gmail=email).first()
    if user and user.otp_decrypted == entered_otp:
        session.pop('otp_attempts', None)
        return jsonify({"message": "Login Success", "status": "success", "redirect": url_for('scanner')})

    session['otp_attempts'] = attempts - 1
    remaining = session['otp_attempts']
    return jsonify({"message": f"Invalid OTP ({remaining} left)", "status": "error", "remaining": remaining})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ─────────────────────────────────────────────────────────
#  SCAN HELPERS
# ─────────────────────────────────────────────────────────

def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()
        expire = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (expire - datetime.datetime.utcnow()).days
        issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
        protocol = conn.version() if hasattr(conn, 'version') else 'TLS'
        return {"valid": True, "expires_in_days": days_left, "issuer": issuer, "protocol": protocol}
    except Exception as e:
        return {"valid": False, "error": str(e)}

SECURITY_HEADERS = {
    "Content-Security-Policy":     {"priority": "critical", "desc": "Prevents XSS and data injection attacks"},
    "Strict-Transport-Security":   {"priority": "critical", "desc": "Forces HTTPS connections"},
    "X-Frame-Options":             {"priority": "high",     "desc": "Prevents clickjacking attacks"},
    "X-Content-Type-Options":      {"priority": "high",     "desc": "Prevents MIME-type sniffing"},
    "Referrer-Policy":             {"priority": "medium",   "desc": "Controls referrer information leakage"},
    "Permissions-Policy":          {"priority": "medium",   "desc": "Controls browser feature access"},
    "Cross-Origin-Resource-Policy":{"priority": "medium",   "desc": "Restricts cross-origin resource sharing"},
    "X-XSS-Protection":            {"priority": "low",      "desc": "Legacy XSS filter header"},
}

def get_score(headers_data, ssl_data, ports, dns_data):
    score = 100
    if not ssl_data.get('valid'):
        score -= 25
    elif ssl_data.get('expires_in_days', 999) < 30:
        score -= 10
    missing_by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for h, d in headers_data.items():
        if not d['present']:
            missing_by_priority[d['priority']] += 1
    score -= missing_by_priority['critical'] * 12
    score -= missing_by_priority['high'] * 7
    score -= missing_by_priority['medium'] * 3
    score -= missing_by_priority['low'] * 1
    high_risk_ports = [p for p in ports if p.get('risk') == 'high']
    score -= len(high_risk_ports) * 5
    if not dns_data.get('spf'):   score -= 5
    if not dns_data.get('dmarc'): score -= 3
    return max(0, min(100, score))

# ─────────────────────────────────────────────────────────
#  WEB SCAN
# ─────────────────────────────────────────────────────────

@app.route("/api/web-scan", methods=["POST"])
def web_scan():
    if 'email' not in session:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json(silent=True) or {}
    url = data.get('url') or request.form.get('website', '')

    if not url:
        return jsonify({"error": "URL required"})

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        hostname = url.split('/')[2].split(':')[0]

        # HTTP request
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "No Title"
            headers = resp.headers
        except Exception as e:
            return jsonify({"error": f"Could not reach {url}: {str(e)}"})

        # SSL
        ssl_data = check_ssl(hostname)

        # Headers check
        headers_data = {}
        for h, meta in SECURITY_HEADERS.items():
            headers_data[h] = {
                "present": h in headers,
                "value": headers.get(h, ""),
                "priority": meta["priority"],
                "desc": meta["desc"]
            }

        # Ports (quick check of common ports)
        common_ports = [
            (21, 'FTP', 'high'), (22, 'SSH', 'medium'), (23, 'Telnet', 'critical'),
            (25, 'SMTP', 'medium'), (53, 'DNS', 'low'), (80, 'HTTP', 'low'),
            (443, 'HTTPS', 'low'), (3306, 'MySQL', 'high'), (5432, 'PostgreSQL', 'high'),
            (6379, 'Redis', 'high'), (8080, 'HTTP-Alt', 'medium'), (27017, 'MongoDB', 'high')
        ]
        open_ports = []
        for port, service, risk in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((hostname, port)) == 0:
                    open_ports.append({"port": port, "service": service, "risk": risk})
                s.close()
            except:
                pass

        # DNS
        spf_ok = False
        dmarc_ok = False
        mail_servers = []
        try:
            import dns.resolver
            try:
                for r in dns.resolver.resolve(hostname, 'TXT'):
                    txt = r.to_text()
                    if 'v=spf1' in txt:
                        spf_ok = True
            except:
                pass
            try:
                for r in dns.resolver.resolve(f'_dmarc.{hostname}', 'TXT'):
                    if 'v=DMARC1' in r.to_text():
                        dmarc_ok = True
            except:
                pass
            try:
                for r in dns.resolver.resolve(hostname, 'MX'):
                    mail_servers.append(str(r.exchange))
            except:
                pass
        except ImportError:
            pass

        dns_data = {"spf": spf_ok, "dmarc": dmarc_ok, "mail_servers": mail_servers[:3]}

        # Subdomains (common ones)
        subdomains = []
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging',
                       'test', 'blog', 'shop', 'support', 'docs', 'm', 'cdn', 'secure']
        for sub in common_subs:
            try:
                socket.gethostbyname(f'{sub}.{hostname}')
                subdomains.append(f'{sub}.{hostname}')
            except:
                pass

        score = get_score(headers_data, ssl_data, open_ports, dns_data)

        result = {
            "url": url, "title": title,
            "score": score,
            "ssl": ssl_data,
            "headers": headers_data,
            "ports": open_ports,
            "dns": dns_data,
            "subdomains": subdomains,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

        # Save to DB
        try:
            missing = [h for h, d in headers_data.items() if not d['present']]
            scan = WebScan(
                email=session['email'],
                website=url,
                title=title,
                missing_headers=", ".join(missing)
            )
            db.session.add(scan)
            db.session.commit()
        except:
            pass

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)})

# ─────────────────────────────────────────────────────────
#  NETWORK SCAN
# ─────────────────────────────────────────────────────────

PORT_RISK = {
    21: ('FTP', 'high'), 22: ('SSH', 'medium'), 23: ('Telnet', 'critical'),
    25: ('SMTP', 'medium'), 53: ('DNS', 'low'), 80: ('HTTP', 'low'),
    110: ('POP3', 'medium'), 135: ('RPC', 'high'), 139: ('NetBIOS', 'high'),
    143: ('IMAP', 'medium'), 443: ('HTTPS', 'low'), 445: ('SMB', 'critical'),
    1433: ('MSSQL', 'critical'), 1521: ('Oracle', 'critical'), 3306: ('MySQL', 'high'),
    3389: ('RDP', 'critical'), 5432: ('PostgreSQL', 'high'), 5900: ('VNC', 'critical'),
    6379: ('Redis', 'high'), 8080: ('HTTP-Alt', 'medium'), 8443: ('HTTPS-Alt', 'low'),
    8888: ('Jupyter', 'high'), 9200: ('Elasticsearch', 'critical'), 27017: ('MongoDB', 'high'),
}

@app.route("/api/network-scan", methods=["POST"])
def network_scan():
    if 'email' not in session:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or request.form.get('ipAddress', '')

    if not ip:
        return jsonify({"error": "IP address required"})

    try:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = ip

        open_ports = []
        for port, (service, risk) in PORT_RISK.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    # Try banner grab
                    banner = ''
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = s.recv(128).decode('utf-8', errors='ignore').strip()[:60]
                    except:
                        pass
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "risk": risk,
                        "banner": banner
                    })
                s.close()
            except:
                pass

        # Score
        risk_weights = {'low': 0, 'medium': 5, 'high': 15, 'critical': 25}
        deduction = sum(risk_weights.get(p['risk'], 0) for p in open_ports)
        score = max(0, 100 - deduction)

        result = {
            "ip": ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "score": score,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

        try:
            scan = NetworkScan(
                email=session['email'],
                ip_address=ip,
                open_ports=str({p['port']: p['service'] for p in open_ports})
            )
            db.session.add(scan)
            db.session.commit()
        except:
            pass

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)})

# ─────────────────────────────────────────────────────────
#  SYSTEM SCAN
# ─────────────────────────────────────────────────────────

@app.route("/api/system-scan", methods=["POST"])
def system_scan():
    if 'email' not in session:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json(silent=True) or {}
    system_name = data.get('system_name') or request.form.get('systemName', 'localhost')

    try:
        try:
            ip = socket.gethostbyname(system_name)
        except:
            ip = '127.0.0.1'

        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        procs = len(psutil.pids())
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime_hours = (datetime.datetime.now() - boot_time).total_seconds() / 3600

        # Vulnerability checks
        checks = []
        if cpu > 90:
            checks.append({"check": "CPU Usage", "value": f"{cpu}%", "status": "warn"})
        else:
            checks.append({"check": "CPU Usage", "value": f"{cpu}%", "status": "ok"})

        if mem.percent > 85:
            checks.append({"check": "Memory Usage", "value": f"{mem.percent}%", "status": "warn"})
        else:
            checks.append({"check": "Memory Usage", "value": f"{mem.percent}%", "status": "ok"})

        if disk.percent > 90:
            checks.append({"check": "Disk Usage", "value": f"{disk.percent}%", "status": "warn"})
        else:
            checks.append({"check": "Disk Usage", "value": f"{disk.percent}%", "status": "ok"})

        checks.append({"check": "Running Processes", "value": str(procs), "status": "ok" if procs < 300 else "warn"})
        checks.append({"check": "System Uptime", "value": f"{uptime_hours:.1f} hours", "status": "ok"})
        checks.append({"check": "OS Platform", "value": platform.system(), "status": "ok"})

        # Score
        warn_count = sum(1 for c in checks if c['status'] == 'warn')
        score = max(0, 100 - warn_count * 15)

        result = {
            "system_name": system_name,
            "ip": ip,
            "os": platform.system(),
            "os_version": platform.version()[:60],
            "processor": platform.processor()[:60] or "Unknown",
            "machine": platform.machine(),
            "cpu_usage": f"{cpu}%",
            "memory_usage": f"{mem.percent}%",
            "disk_usage": f"{disk.percent}%",
            "running_processes": procs,
            "uptime_hours": round(uptime_hours, 1),
            "vulnerability_checks": checks,
            "score": score,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

        try:
            scan = SystemScan(
                email=session['email'],
                hostname=system_name,
                ip_address=ip,
                os=platform.system(),
                cpu_usage=f"{cpu}%",
                memory_usage=f"{mem.percent}%"
            )
            db.session.add(scan)
            db.session.commit()
        except:
            pass

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)})

# ─────────────────────────────────────────────────────────
#  HISTORY API
# ─────────────────────────────────────────────────────────

@app.route("/api/history")
def history():
    if 'email' not in session:
        return jsonify([])
    email = session['email']
    results = []
    for scan in WebScan.query.filter_by(email=email).order_by(WebScan.timestamp.desc()).limit(5).all():
        results.append({"type": "web", "target": scan.website, "timestamp": str(scan.timestamp)})
    for scan in NetworkScan.query.filter_by(email=email).order_by(NetworkScan.timestamp.desc()).limit(5).all():
        results.append({"type": "network", "target": scan.ip_address, "timestamp": str(scan.timestamp)})
    for scan in SystemScan.query.filter_by(email=email).order_by(SystemScan.timestamp.desc()).limit(5).all():
        results.append({"type": "system", "target": scan.hostname, "timestamp": str(scan.timestamp)})
    results.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(results)

# ─────────────────────────────────────────────────────────
#  REPORT PDF (server-side generation)
# ─────────────────────────────────────────────────────────

@app.route("/generate_report", methods=["POST"])
def generate_report():
    """Generate a PDF report from scan data (called from frontend)."""
    # The frontend handles PDF generation via the browser's print dialog
    # This endpoint is kept for future server-side PDF generation
    return jsonify({"status": "use_browser_print"})

# ─────────────────────────────────────────────────────────
#  LEGACY ROUTES (backward compat)
# ─────────────────────────────────────────────────────────

@app.route("/scan_website", methods=["POST"])
def scan_website():
    return web_scan()

@app.route("/start_scan", methods=["POST"])
def start_scan():
    return network_scan()

@app.route("/scan_system", methods=["POST"])
def scan_system_legacy():
    return system_scan()

if __name__ == "__main__":
    app.run(debug=True)