from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
import sqlite3
from functools import wraps
import os
import subprocess
import threading
import time
import json
import requests
import signal
import sys
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart
from reportlab.platypus.flowables import KeepTogether
from user import user_bp
from gemini_helper import get_mitigation, get_bulk_mitigations

app = Flask(__name__)
app.secret_key = 'dev_key_change_in_prod'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.register_blueprint(user_bp)

# -----------------------
# Custom login required decorator using sessions
# -----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('user.login'))
        return f(*args, **kwargs)
    return decorated_function

# -----------------------
# Configuration (env-first)
# -----------------------
ZAP_API_URL = os.getenv('ZAP_API_URL', 'http://localhost:8080/JSON')
ZAP_API_KEY = os.getenv('ZAP_API_KEY', 'd0vh061p7vptaib3f8g15na2jf')

NUCLEI_BIN = os.getenv('NUCLEI_BIN', r'C:\Tools\nuclei\nuclei.exe')

NUCLEI_SEVERITIES = os.getenv('NUCLEI_SEVERITIES', 'critical,high,medium,low')
NUCLEI_RL = os.getenv('NUCLEI_RL', '150')  # Increased rate limit from 50 to 150
NUCLEI_C = os.getenv('NUCLEI_C', '50')  # Increased concurrency from 25 to 50
NUCLEI_TIMEOUT = os.getenv('NUCLEI_TIMEOUT', '5')  # Reduced timeout from 10 to 5 seconds
NUCLEI_EXTRA_ARGS = os.getenv('NUCLEI_EXTRA_ARGS', '')

NUCLEI_FAST = os.getenv('NUCLEI_FAST', '1')
NUCLEI_FAST_SEVERITIES = os.getenv('NUCLEI_FAST_SEVERITIES', 'critical,high,medium,low')
NUCLEI_FAST_TAGS = os.getenv('NUCLEI_FAST_TAGS', 'cve,default,exposure,misconfig,vulnerabilities')  # Added vulnerabilities tag
NUCLEI_MAX_SECONDS = int(os.getenv('NUCLEI_MAX_SECONDS', '60'))  # Increased from 45 to 60 seconds
NUCLEI_QUICK_TEMPLATES = os.getenv('NUCLEI_QUICK_TEMPLATES', '')

ARTIFACTS_DIR = os.getenv('ARTIFACTS_DIR', 'scans')
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

# -----------------------
# SQLite setup – ADD scan_key
# -----------------------
def get_db():
    conn = sqlite3.connect('scans.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_key INTEGER UNIQUE,
                        url TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        results TEXT
                     )''')
        # Add scan_key if old DB exists
        try:
            c.execute('ALTER TABLE scans ADD COLUMN scan_key INTEGER UNIQUE')
        except sqlite3.OperationalError:
            pass
        # ADD MODE COLUMN
        try:
            c.execute('ALTER TABLE scans ADD COLUMN mode TEXT')
        except sqlite3.OperationalError:
            pass

        # Create scheduled_scans table
        c.execute('''CREATE TABLE IF NOT EXISTS scheduled_scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        interval_minutes INTEGER DEFAULT 15,
                        enabled INTEGER DEFAULT 1,
                        last_scan_id INTEGER,
                        last_run DATETIME,
                        next_run DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        created_by INTEGER,
                        FOREIGN KEY(created_by) REFERENCES users(id)
                     )''')

        # Create notifications table
        c.execute('''CREATE TABLE IF NOT EXISTS notifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        message TEXT NOT NULL,
                        url TEXT,
                        has_differences INTEGER DEFAULT 0,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_read INTEGER DEFAULT 0,
                        user_id INTEGER,
                        FOREIGN KEY(scan_id) REFERENCES scans(scan_key),
                        FOREIGN KEY(user_id) REFERENCES users(id)
                     )''')

        db.commit()
        db.close()

# -----------------------
# Scan status tracking
# -----------------------
scans_status = {}

# -----------------------
# ZAP helpers
# -----------------------
def check_zap_api():
    """Verify ZAP API is accessible."""
    url = f'{ZAP_API_URL}/core/view/version'
    params = {'apikey': ZAP_API_KEY} if ZAP_API_KEY else {}
    try:
        print(f"Testing ZAP API at {url}")
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            print(f"ZAP API accessible: {response.json()}")
            return True
        else:
            print(f"ZAP API returned status {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"ZAP API check failed: {str(e)}")
        return False

def start_zap_daemon():
    zap_path = r'C:\Program Files\ZAP\Zed Attack Proxy\zap.bat'
    print(f"Starting ZAP daemon at {zap_path}")
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    cmd = [zap_path, '-daemon', '-port', '8080', '-host', 'localhost',
           '-config', 'api.enabled=true', '-config', 'api.disablekey=true',
           '-config', 'api.addrs.addr.name=.*', '-config', 'api.addrs.addr.regex=true']
    try:
        subprocess.Popen(cmd, creationflags=creation_flags)
    except Exception as e:
        print(f"Failed to start ZAP process: {e}")
        return False

    print("Waiting for ZAP daemon to start...")
    for attempt in range(20):
        time.sleep(15)
        if check_zap_api():
            print("ZAP daemon is ready")
            return True
        print(f"Retry {attempt + 1}/20...")
    print("ZAP daemon failed to start after retries")
    return False

def run_zap_scan(target_url, scan_id):
    """ZAP spider + active scan + alerts collection."""
    try:
        if not check_zap_api():
            raise Exception("ZAP API is not accessible")
        print(f"Starting ZAP scan for {target_url}")
        scans_status[scan_id]['status'] = 'running'
        scans_status[scan_id]['progress'] = 10

        params = {'apikey': ZAP_API_KEY} if ZAP_API_KEY else {}
        requests.get(f'{ZAP_API_URL}/spider/action/setOptionMaxDepth/?Integer=5', params=params, timeout=10)
        requests.get(f'{ZAP_API_URL}/spider/action/setOptionMaxChildren/?Integer=10', params=params, timeout=10)

        sp_params = dict(params)
        sp_params.update({'url': target_url, 'inScopeOnly': 'false'})
        response = requests.get(f'{ZAP_API_URL}/spider/action/scan/', params=sp_params, timeout=10)
        scan_id_zap = response.json().get('scan')
        print(f"Started spider scan: {scan_id_zap}")

        while True:
            status = requests.get(f'{ZAP_API_URL}/spider/view/status/?scanId={scan_id_zap}', params=params, timeout=10).json()
            progress = int(status.get('status', 0))
            scans_status[scan_id]['progress'] = 10 + (progress / 2)
            if progress >= 100:
                break
            time.sleep(2)

        scans_status[scan_id]['progress'] = 60
        as_params = {'url': target_url, 'recurse': 'true', 'inScopeOnly': 'true'}
        if ZAP_API_KEY:
            as_params['apikey'] = ZAP_API_KEY
        response = requests.get(f'{ZAP_API_URL}/ascan/action/scan/', params=as_params, timeout=10)
        ascan_id = response.json().get('scan')
        print(f"Started active scan: {ascan_id}")

        while True:
            status = requests.get(f'{ZAP_API_URL}/ascan/view/status/?scanId={ascan_id}', params=params, timeout=10).json()
            progress = int(status.get('status', 0))
            scans_status[scan_id]['progress'] = 60 + (progress / 4)
            if progress >= 100:
                break
            time.sleep(5)

        al_params = {'baseurl': target_url}
        if ZAP_API_KEY:
            al_params['apikey'] = ZAP_API_KEY
        alerts = requests.get(f'{ZAP_API_URL}/core/view/alerts/', params=al_params, timeout=15).json().get('alerts', [])

        # Deduplicate ZAP alerts based on type + URL combination
        seen_alerts = set()
        zap_results = []
        for alert in alerts:
            alert_type = alert.get('alert', 'Unknown')
            alert_url = alert.get('url', '')
            alert_key = f"{alert_type}|{alert_url}"

            if alert_key not in seen_alerts:
                seen_alerts.add(alert_key)
                zap_results.append({
                    'type': alert_type,
                    'severity': alert.get('riskcode', 'Medium'),
                    'url': alert_url,
                    'description': (alert.get('description') or '')[:200]
                })

        scans_status[scan_id].setdefault('results', {})['zap'] = zap_results
        print(f"ZAP scan completed with {len(zap_results)} unique alerts (deduplicated from {len(alerts)} total)")
    except Exception as e:
        print("ZAP Error:", str(e))
        scans_status[scan_id]['status'] = 'error'
        scans_status[scan_id]['error'] = f'ZAP: {str(e)}'
        raise

def zap_export_urls(target_url):
    """Return list of URLs ZAP knows for the base URL."""
    params = {'baseurl': target_url}
    if ZAP_API_KEY:
        params['apikey'] = ZAP_API_KEY
    try:
        data = requests.get(f'{ZAP_API_URL}/core/view/urls/', params=params, timeout=15).json()
        urls = data.get('urls', [])
        return sorted(set(urls))
    except Exception as e:
        print(f"Failed to export URLs from ZAP: {e}")
        return []

# -----------------------
# Nuclei helpers
# -----------------------
def _split_quick_templates(val: str):
    items = []
    for part in val.split(','):
        p = part.strip()
        if p:
            items.append(p)
    return items

def _kill_process_tree(proc: subprocess.Popen):
    """Robustly kill a process and its children on Windows & *nix."""
    try:
        if sys.platform.startswith('win'):
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc.kill()
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
    except Exception as e:
        print(f"Failed to kill process tree: {e}")

def _run_nuclei_command(cmd, max_seconds, capture=True):
    """Run nuclei with a hard timeout and clean termination; returns (returncode, stdout, stderr)."""
    print("Executing:", ' '.join(cmd))
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        if capture:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    creationflags=creation_flags)
        else:
            proc = subprocess.Popen(cmd, creationflags=creation_flags)
        try:
            stdout, stderr = proc.communicate(timeout=max_seconds)
        except subprocess.TimeoutExpired:
            print(f"Nuclei reached hard cap ({max_seconds}s); terminating...")
            _kill_process_tree(proc)
            return -999, "", f"timeout@{max_seconds}s"
        return proc.returncode, stdout if capture else "", stderr if capture else ""
    except FileNotFoundError:
        return -998, "", "nuclei binary not found"
    except Exception as e:
        return -997, "", str(e)

def build_nuclei_quick_cmd_single(target_url, jsonl_path):
    base = [NUCLEI_BIN, '-u', target_url, '-jsonl', '-o', jsonl_path,
            '-silent', '-no-color', '-retries', '0', '-duc', '-no-interactsh',
            '-stats']  # Added stats for better visibility

    quick_templates = _split_quick_templates(NUCLEI_QUICK_TEMPLATES) if NUCLEI_QUICK_TEMPLATES else []
    if quick_templates:
        for t in quick_templates:
            base.extend(['-t', t])
        base.extend(['-severity', NUCLEI_FAST_SEVERITIES])
        base.extend(['-c', '100', '-rl', '250', '-timeout', '3', '-bulk-size', '50'])
    else:
        base.extend([
            '-severity', NUCLEI_FAST_SEVERITIES,
            '-tags', NUCLEI_FAST_TAGS,
            '-c', '150',  # Increased concurrency
            '-rl', '300',  # Increased rate limit
            '-timeout', '3',
            '-bulk-size', '50',  # Process 50 requests at once
            '-stats-json'  # JSON stats for better parsing
        ])

    if NUCLEI_EXTRA_ARGS:
        base.extend(NUCLEI_EXTRA_ARGS.split())
    return base

def build_nuclei_cmd_list(urls_file, jsonl_path):
    base = [NUCLEI_BIN, '-list', urls_file, '-jsonl', '-o', jsonl_path,
            '-silent', '-no-color', '-retries', '0', '-duc', '-no-interactsh',
            '-severity', NUCLEI_SEVERITIES, '-c', NUCLEI_C, '-rl', NUCLEI_RL,
            '-timeout', NUCLEI_TIMEOUT, '-bulk-size', '50', '-stats']
    if NUCLEI_EXTRA_ARGS:
        base.extend(NUCLEI_EXTRA_ARGS.split())
    return base

def run_nuclei_scan_single(target_url, scan_id, fast=True):
    """Run nuclei against a single URL; save JSONL and parse results."""
    if not os.path.exists(NUCLEI_BIN):
        scans_status[scan_id]['status'] = 'error'
        scans_status[scan_id]['error'] = f'Nuclei binary not found at {NUCLEI_BIN}'
        print(scans_status[scan_id]['error'])
        return

    jsonl_path = os.path.join(ARTIFACTS_DIR, f'nuclei_{scan_id}.jsonl')
    if fast and NUCLEI_FAST == '1':
        cmd = build_nuclei_quick_cmd_single(target_url, jsonl_path)
        max_secs = NUCLEI_MAX_SECONDS
    else:
        cmd = [NUCLEI_BIN, '-u', target_url, '-severity', NUCLEI_SEVERITIES,
               '-rl', NUCLEI_RL, '-c', NUCLEI_C, '-timeout', NUCLEI_TIMEOUT,
               '-jsonl', '-o', jsonl_path, '-silent', '-no-color', '-retries', '0', '-duc', '-no-interactsh']
        if NUCLEI_EXTRA_ARGS:
            cmd.extend(NUCLEI_EXTRA_ARGS.split())
        max_secs = 180

    print(f"Running nuclei (single): {' '.join(cmd)}")
    print(f"Target URL: {target_url}")
    print(f"Output file: {jsonl_path}")
    print(f"Max execution time: {max_secs}s")

    # Clear any old JSONL file
    if os.path.exists(jsonl_path):
        try:
            os.remove(jsonl_path)
            print(f"Removed old JSONL file: {jsonl_path}")
        except Exception as e:
            print(f"Failed to remove old JSONL: {e}")

    start_time = time.time()
    rc, _out, err = _run_nuclei_command(cmd, max_secs)
    elapsed = time.time() - start_time

    print(f"Nuclei completed in {elapsed:.2f}s with return code: {rc}")
    if _out:
        print(f"Nuclei stdout: {_out[:500]}")  # First 500 chars
    if err:
        print(f"Nuclei stderr: {err[:500]}")  # First 500 chars

    if rc == -998:
        scans_status[scan_id]['status'] = 'error'
        scans_status[scan_id]['error'] = f'Nuclei: binary not found at {NUCLEI_BIN}'
        print(f"ERROR: Nuclei binary not found at {NUCLEI_BIN}")
        print("Please ensure Nuclei is installed and the path is correct.")
        return
    if rc == -999:
        scans_status[scan_id].setdefault('results', {})
        scans_status[scan_id]['results'].setdefault('meta', {})['nuclei_timeout'] = max_secs
        print(f"WARNING: Nuclei scan timed out after {max_secs}s, partial results may be available")
    elif rc not in (0, 1):
        print(f"WARNING: Nuclei execution error (rc={rc}): {err}")
        # Don't fail the whole scan - just log and continue with empty results

    # Wait a moment for file to be written
    time.sleep(0.5)

    # Check if JSONL file was created
    if os.path.exists(jsonl_path):
        file_size = os.path.getsize(jsonl_path)
        print(f"JSONL file created: {jsonl_path} (size: {file_size} bytes)")

        # Try to read raw file to debug
        if file_size > 0:
            try:
                with open(jsonl_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    print(f"JSONL contains {len(lines)} lines")
                    if len(lines) > 0:
                        print(f"First line sample: {lines[0][:100]}...")
            except Exception as e:
                print(f"Error reading JSONL for debug: {e}")
    else:
        print(f"WARNING: JSONL file not created at {jsonl_path}")
        print(f"This usually means:")
        print(f"  1. No vulnerabilities were found (normal)")
        print(f"  2. Network connectivity issues")
        print(f"  3. Target blocked the scan")

    nuclei_results = parse_nuclei_jsonl(jsonl_path)
    scans_status[scan_id].setdefault('results', {})['nuclei'] = nuclei_results
    print(f"Nuclei findings (single): {len(nuclei_results)} vulnerabilities found")

    # Additional info about why no results
    if len(nuclei_results) == 0:
        print("INFO: No vulnerabilities found. This could mean:")
        print("  - The target has no known CVEs or misconfigurations")
        print("  - The target is properly secured")
        print("  - Network/firewall is blocking Nuclei probes")
        print("  - Templates need updating: nuclei -update-templates")
        print(f"  - Consider increasing timeout (current: {max_secs}s)")
        print(f"  - Try running manually: {' '.join(cmd[:10])}...")

def run_nuclei_scan_list(urls_file, scan_id):
    """Run nuclei against a list of URLs; save JSONL and parse results."""
    if not os.path.exists(NUCLEI_BIN):
        scans_status[scan_id]['status'] = 'error'
        scans_status[scan_id]['error'] = f'Nuclei binary not found at {NUCLEI_BIN}'
        print(scans_status[scan_id]['error'])
        return

    jsonl_path = os.path.join(ARTIFACTS_DIR, f'nuclei_{scan_id}.jsonl')
    cmd = build_nuclei_cmd_list(urls_file, jsonl_path)

    print(f"Running nuclei (list): {' '.join(cmd)}")
    rc, _out, err = _run_nuclei_command(cmd, max_seconds=180)
    if rc == -998:
        scans_status[scan_id]['status'] = 'error'
        scans_status[scan_id]['error'] = f'Nuclei: binary not found at {NUCLEI_BIN}'
        return
    if rc not in (0, 1, -999):
        print(f"Nuclei execution error: {err}")
        scans_status[scan_id]['status'] = 'error'
        scans_status[scan_id]['error'] = f'Nuclei: {err or 'non-zero exit'}'

    nuclei_results = parse_nuclei_jsonl(jsonl_path)
    scans_status[scan_id].setdefault('results', {})['nuclei'] = nuclei_results
    print(f"Nuclei findings (list): {len(nuclei_results)}")

def parse_nuclei_jsonl(jsonl_path):
    results = []
    if not os.path.exists(jsonl_path):
        return results
    try:
        with open(jsonl_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    results.append({
                        'template': rec.get('template-id', ''),
                        'name': (rec.get('info', {}) or {}).get('name', ''),
                        'severity': (rec.get('info', {}) or {}).get('severity', ''),
                        'type': rec.get('type', ''),
                        'matched': rec.get('matched-at', ''),
                        'tags': (rec.get('info', {}) or {}).get('tags', ''),
                        'reference': (rec.get('info', {}) or {}).get('reference', [])
                    })
                except Exception as ie:
                    print(f"Nuclei parse error: {ie}")
                    continue
    except Exception as e:
        print(f"Failed reading nuclei JSONL: {e}")
    return results

# -----------------------
# Orchestrators for modes
# -----------------------
def run_scan_normal(target_url, scan_id):
    """ZAP only"""
    run_zap_scan(target_url, scan_id)
    scans_status[scan_id]['status'] = 'done'
    scans_status[scan_id]['progress'] = 100

def run_scan_api(target_url, scan_id):
    """Fast Nuclei only (hard-capped)"""
    scans_status[scan_id]['status'] = 'running'
    scans_status[scan_id]['progress'] = 10
    start = time.time()
    run_nuclei_scan_single(target_url, scan_id, fast=True)
    elapsed = time.time() - start
    if elapsed < NUCLEI_MAX_SECONDS:
        scans_status[scan_id]['progress'] = 80
        time.sleep(0.1)
    # Always mark as done - empty results are OK
    scans_status[scan_id]['status'] = 'done'
    scans_status[scan_id]['progress'] = 100

def run_scan_deep(target_url, scan_id):
    """ZAP + Nuclei on ZAP-discovered URLs"""
    run_zap_scan(target_url, scan_id)

    scans_status[scan_id]['status'] = 'running'
    scans_status[scan_id]['progress'] = max(scans_status[scan_id].get('progress', 60), 85)
    urls = zap_export_urls(target_url)
    urls_file = os.path.join(ARTIFACTS_DIR, f'urls_{scan_id}.txt')
    with open(urls_file, 'w', encoding='utf-8') as f:
        for u in urls:
            f.write(u + '\n')
    print(f"Deep mode: exported {len(urls)} URLs to {urls_file}")

    run_nuclei_scan_list(urls_file, scan_id)
    scans_status[scan_id]['status'] = 'done'
    scans_status[scan_id]['progress'] = 100

# -----------------------
# Main run_scan – saves scan_key + ONE JSON file
# -----------------------
def run_scan(target_url, scan_id, mode):
    try:
        scans_status[scan_id]['mode'] = mode
        if mode == 'normal':
            run_scan_normal(target_url, scan_id)
        elif mode == 'api':
            run_scan_api(target_url, scan_id)
        elif mode == 'deep':
            run_scan_deep(target_url, scan_id)
        else:
            raise ValueError(f"Unknown mode: {mode}")

        print(f"Saving scan results for scan_id {scan_id}: {scans_status[scan_id]}")
        results = scans_status[scan_id].get('results', {})
        results_json = json.dumps(results)

        db = get_db()
        c = db.cursor()
        c.execute('INSERT INTO scans (scan_key, url, mode, results) VALUES (?, ?, ?, ?)', (scan_id, target_url, mode, results_json))
        db.commit()
        db.close()

        # Save ONLY ONE JSON file
        json_path = os.path.join(ARTIFACTS_DIR, f'scan_{scan_id}.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"Saved scan results with mitigations to {json_path}")

    except Exception as e:
        print(f"run_scan error: {e}")
        scans_status[scan_id]['status'] = 'error'
        scans_status[scan_id]['error'] = f'Controller: {e}'

# -----------------------
# Routes
# -----------------------

# Landing page redirect
@app.route('/')
def index():
    return redirect(url_for('user.landing'))

# DASHBOARD (MAIN PAGE)
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id, scan_key, url, timestamp FROM scans ORDER BY timestamp DESC')
    history = c.fetchall()
    db.close()
    return render_template('dashboard.html', history=history)

# SCAN FORM PAGE
@app.route('/scan')
def scan_page():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    target_url = request.form['url'].strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    mode = request.form.get('mode', 'normal').strip().lower()
    scan_id = int(time.time())
    scans_status[scan_id] = {'status': 'queued', 'progress': 0, 'results': {}, 'scan_id': scan_id, 'mode': mode}
    threading.Thread(target=run_scan, args=(target_url, scan_id, mode), daemon=True).start()
    return redirect(url_for('status', scan_id=scan_id))

@app.route('/status/<int:scan_id>')
def status(scan_id):
    return render_template('status.html', scan_id=scan_id)

@app.route('/api/status/<int:scan_id>')
def api_status(scan_id):
    status = scans_status.get(scan_id, {'status': 'not_found'})
    return jsonify(status)

@app.route('/api/mitigation/<int:scan_id>')
def get_scan_mitigations(scan_id):
    """Get AI-generated mitigation advice for all vulnerabilities in a scan and save to database."""
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM scans WHERE scan_key = ?', (scan_id,))
    row = c.fetchone()

    if not row:
        db.close()
        return jsonify({'error': 'Scan not found'}), 404

    results = json.loads(row['results'] or '{}')

    # Check if mitigations already exist
    if 'mitigations' in results and results['mitigations']:
        db.close()
        return jsonify({'mitigations': results['mitigations'], 'cached': True})

    zap_results = results.get('zap', [])
    nuclei_results = results.get('nuclei', [])

    # Collect unique vulnerability names
    vuln_names = []

    # Add ZAP vulnerability types
    for alert in zap_results:
        vuln_name = alert.get('type', 'Unknown')
        if vuln_name not in vuln_names:
            vuln_names.append(vuln_name)

    # Add Nuclei vulnerability names
    for item in nuclei_results:
        vuln_name = item.get('name', item.get('template', 'Unknown'))
        if vuln_name not in vuln_names:
            vuln_names.append(vuln_name)

    # Get mitigations using Gemini API (limit to conserve credits)
    print(f"Fetching mitigations for {len(vuln_names)} vulnerabilities...")
    mitigations = get_bulk_mitigations(vuln_names, max_requests=10)

    # Add mitigations to ZAP results
    for alert in zap_results:
        vuln_name = alert.get('type', 'Unknown')
        alert['mitigation'] = mitigations.get(vuln_name, 'Update software, apply patches, review configuration, and follow security best practices.')

    # Add mitigations to Nuclei results
    for item in nuclei_results:
        vuln_name = item.get('name', item.get('template', 'Unknown'))
        item['mitigation'] = mitigations.get(vuln_name, 'Update software, apply patches, review configuration, and follow security best practices.')

    # Store mitigations in results
    results['mitigations'] = mitigations
    results['zap'] = zap_results
    results['nuclei'] = nuclei_results

    # Save updated results back to database
    results_json = json.dumps(results)
    c.execute('UPDATE scans SET results = ? WHERE scan_key = ?', (results_json, scan_id))
    db.commit()

    # Also save to JSON file
    json_path = os.path.join(ARTIFACTS_DIR, f'scan_{scan_id}.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    db.close()
    print(f"Saved mitigations for scan {scan_id}")

    return jsonify({'mitigations': mitigations, 'cached': False})

@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get all notifications for the current user"""
    try:
        user_id = session.get('user_id')
        db = get_db()

        # Get unread notifications
        notifications = db.execute('''
            SELECT * FROM notifications
            WHERE (user_id = ? OR user_id IS NULL) AND is_read = 0
            ORDER BY timestamp DESC
            LIMIT 10
        ''', (user_id,)).fetchall()

        db.close()

        notifications_list = []
        for notif in notifications:
            notifications_list.append({
                'id': notif['id'],
                'scan_id': notif['scan_id'],
                'message': notif['message'],
                'url': notif['url'],
                'has_differences': notif['has_differences'],
                'timestamp': notif['timestamp'],
                'is_read': notif['is_read']
            })

        return jsonify({'notifications': notifications_list, 'count': len(notifications_list)})
    except Exception as e:
        print(f"Error fetching notifications: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        db = get_db()
        db.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
        db.commit()
        db.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read for the current user"""
    try:
        user_id = session.get('user_id')
        db = get_db()
        db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ? OR user_id IS NULL', (user_id,))
        db.commit()
        db.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error marking all notifications as read: {e}")
        return jsonify({'error': str(e)}), 500

# VIEW SCAN DETAILS (detail.html)
@app.route('/detail/<int:scan_id>')
def scan_detail(scan_id):
    """Show a nice HTML page with ZAP + Nuclei results."""
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM scans WHERE scan_key = ?', (scan_id,))
    row = c.fetchone()
    db.close()

    if not row:
        flash('Scan not found.', 'danger')
        return redirect(url_for('dashboard'))

    results = json.loads(row['results'] or '{}')
    return render_template(
        'detail.html',
        scan=row,
        zap_results=results.get('zap', []),
        nuclei_results=results.get('nuclei', [])
    )

# SCHEDULED SCANS
@app.route('/scheduled')
@login_required
def scheduled_scans():
    db = get_db()
    scheduled = db.execute('SELECT * FROM scheduled_scans ORDER BY created_at DESC').fetchall()
    db.close()
    return render_template('scheduled_scans.html', scheduled=scheduled)

@app.route('/scheduled/add', methods=['POST'])
@login_required
def add_scheduled_scan():
    url = request.form['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    mode = request.form.get('mode', 'normal').strip().lower()
    interval = int(request.form.get('interval', 15))

    from datetime import datetime, timedelta
    next_run = datetime.now() + timedelta(minutes=interval)

    db = get_db()
    c = db.cursor()
    c.execute('''INSERT INTO scheduled_scans (url, mode, interval_minutes, next_run, created_by)
                 VALUES (?, ?, ?, ?, ?)''',
              (url, mode, interval, next_run, session.get('user_id')))
    db.commit()
    db.close()

    flash('Scheduled scan created successfully!', 'success')
    return redirect(url_for('scheduled_scans'))

@app.route('/scheduled/delete/<int:sched_id>', methods=['POST'])
@login_required
def delete_scheduled_scan(sched_id):
    db = get_db()
    db.execute('DELETE FROM scheduled_scans WHERE id = ?', (sched_id,))
    db.commit()
    db.close()
    flash('Scheduled scan deleted.', 'success')
    return redirect(url_for('scheduled_scans'))

@app.route('/scheduled/toggle/<int:sched_id>', methods=['POST'])
@login_required
def toggle_scheduled_scan(sched_id):
    db = get_db()
    current = db.execute('SELECT enabled FROM scheduled_scans WHERE id = ?', (sched_id,)).fetchone()
    new_status = 0 if current['enabled'] == 1 else 1
    db.execute('UPDATE scheduled_scans SET enabled = ? WHERE id = ?', (new_status, sched_id))
    db.commit()
    db.close()
    flash('Scheduled scan updated.', 'success')
    return redirect(url_for('scheduled_scans'))

# DELETE SCAN – only DB + ONE JSON file
@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Delete DB row + scan_{scan_id}.json"""
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM scans WHERE scan_key = ?', (scan_id,))
    row = c.fetchone()

    if row:
        # Delete the ONE JSON file
        json_path = os.path.join(ARTIFACTS_DIR, f'scan_{scan_id}.json')
        if os.path.exists(json_path):
            try:
                os.remove(json_path)
            except Exception as e:
                print(f"Failed to delete {json_path}: {e}")

        # Delete DB row
        c.execute('DELETE FROM scans WHERE scan_key = ?', (scan_id,))
        db.commit()
        flash('Scan deleted successfully.', 'success')
    else:
        flash('Scan not found.', 'danger')

    db.close()
    return redirect(url_for('dashboard'))

# -----------------------
# ENHANCED PDF REPORT FUNCTION WITH MORE GRAPHS AND MITIGATION
# -----------------------
def create_pdf_report(scan_id, scan_data, zap_results, nuclei_results):
    pdf_path = os.path.join(ARTIFACTS_DIR, f'report_{scan_id}.pdf')

    # Increase margins for better readability
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=0.75*inch,
        rightMargin=0.75*inch,
        topMargin=0.8*inch,
        bottomMargin=0.6*inch
    )

    styles = getSampleStyleSheet()

    # Custom Styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#6a11cb')
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        textColor=colors.HexColor('#2575fc')
    )

    # Smaller font style for tables
    table_style = ParagraphStyle(
        'TableStyle',
        parent=styles['Normal'],
        fontSize=7,
        leading=8,
        alignment=TA_LEFT
    )

    story = []

    # Header
    story.append(Paragraph("SecureScanX", title_style))
    story.append(Paragraph("<font size=12 color=#55a3ff>Vulnerability Scan Report</font>", styles['Normal']))
    story.append(Spacer(1, 20))

    # Info Table
    info_data = [
        ['Target URL', scan_data['url']],
        ['Scan Mode', (scan_data['mode'] if 'mode' in scan_data and scan_data['mode'] else 'unknown').capitalize()],
        ['Scanned On', scan_data['timestamp']],
        ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
    ]

    info_table = Table(info_data, colWidths=[1.5*inch, 5*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#6a11cb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('FONTSIZE', (0,1), (-1,-1), 9),
    ]))

    story.append(info_table)
    story.append(Spacer(1, 30))

    # Severity Count calculation
    severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for a in zap_results:
        s = a.get('severity', '').title()
        if s in severity_count:
            severity_count[s] += 1
    for n in nuclei_results:
        s = n.get('severity', '').capitalize()
        if s in severity_count:
            severity_count[s] += 1

    total = sum(severity_count.values())

    # Chart 1: Severity Distribution (Pie Chart)
    if total > 0:
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 100
        pie.y = 20
        pie.width = pie.height = 160
        pie.data = [v for v in severity_count.values() if v > 0]
        pie.labels = [k for k, v in severity_count.items() if v > 0]
        pie.slices.strokeWidth = 0.5
        pie.slices.strokeColor = colors.white

        # Define colors for each severity
        severity_colors = {
            'Critical': colors.HexColor('#ff0844'),
            'High': colors.HexColor('#ff6b6b'),
            'Medium': colors.HexColor('#feca57'),
            'Low': colors.HexColor('#48dbfb'),
            'Info': colors.HexColor('#17a2b8')
        }

        # Apply colors
        for i, label in enumerate(pie.labels):
            if label in severity_colors:
                pie.slices[i].fillColor = severity_colors[label]

        drawing.add(pie)
        story.append(Paragraph("Severity Distribution", heading_style))
        story.append(drawing)
        story.append(Spacer(1, 20))

    # Chart 2: Finding Source Comparison (Bar Chart)
    if zap_results or nuclei_results:
        story.append(Paragraph("Finding Source Comparison", heading_style))
        drawing2 = Drawing(400, 200)
        bar = VerticalBarChart()
        bar.x = 50
        bar.y = 50
        bar.height = 125
        bar.width = 300
        bar.data = [[len(zap_results), len(nuclei_results)]]
        bar.categoryAxis.categoryNames = ['ZAP', 'Nuclei']
        bar.bars[0].fillColor = colors.HexColor('#2575fc')
        bar.valueAxis.valueMin = 0
        bar.valueAxis.valueMax = max(len(zap_results), len(nuclei_results)) + 5
        bar.categoryAxis.labels.fontSize = 10
        bar.valueAxis.labels.fontSize = 10
        drawing2.add(bar)
        story.append(drawing2)
        story.append(Spacer(1, 20))

    # Chart 3: Risk Score Gauge
    risk_score = min(100, (severity_count.get('Critical', 0) * 10) +
                           (severity_count.get('High', 0) * 5) +
                           (severity_count.get('Medium', 0) * 2) +
                           severity_count.get('Low', 0))

    story.append(Paragraph("Risk Assessment", heading_style))
    story.append(Paragraph(f"<font size=14><b>Risk Score: {risk_score}/100</b></font>", styles['Normal']))
    story.append(Spacer(1, 10))

    if risk_score >= 70:
        risk_text = "<font color=#ff0844><b>CRITICAL RISK</b></font> - Immediate action required!"
    elif risk_score >= 50:
        risk_text = "<font color=#ff6b6b><b>HIGH RISK</b></font> - Action required soon."
    elif risk_score >= 30:
        risk_text = "<font color=#feca57><b>MEDIUM RISK</b></font> - Monitor and patch."
    else:
        risk_text = "<font color=#48dbfb><b>LOW RISK</b></font> - Continue monitoring."

    story.append(Paragraph(risk_text, styles['Normal']))
    story.append(Spacer(1, 20))

    # Chart 4: Top Vulnerability Types (Horizontal Bar)
    type_map = {}
    for a in zap_results:
        vtype = a.get('type', 'Unknown').split('-')[0].strip()[:20]
        type_map[vtype] = type_map.get(vtype, 0) + 1

    for n in nuclei_results:
        tags = n.get('tags', '')
        vtype = tags.split(',')[0].strip()[:20] if tags else 'other'
        type_map[vtype] = type_map.get(vtype, 0) + 1

    if type_map:
        top_types = sorted(type_map.items(), key=lambda x: x[1], reverse=True)[:5]
        story.append(Paragraph("Top 5 Vulnerability Types", heading_style))

        drawing3 = Drawing(400, 150)
        hbar = HorizontalBarChart()
        hbar.x = 100
        hbar.y = 20
        hbar.height = 100
        hbar.width = 250
        hbar.data = [[item[1] for item in top_types]]
        hbar.categoryAxis.categoryNames = [item[0] for item in top_types]
        hbar.bars[0].fillColor = colors.HexColor('#a855f7')
        hbar.valueAxis.valueMin = 0
        hbar.categoryAxis.labels.fontSize = 8
        hbar.valueAxis.labels.fontSize = 8
        drawing3.add(hbar)
        story.append(drawing3)
        story.append(Spacer(1, 20))

    story.append(PageBreak())

    # MITIGATION SECTION
    story.append(Paragraph("Recommended Mitigations", heading_style))
    story.append(Spacer(1, 10))

    # Collect mitigations from stored data
    try:
        mitigation_data = [['Vulnerability', 'Recommended Mitigation']]

        # Add ZAP mitigations (limit to first 10)
        for alert in zap_results[:10]:
            vuln_name = alert.get('type', 'Unknown')[:40]
            mitigation = alert.get('mitigation', 'Update software, apply patches, review configuration, and follow security best practices.')
            vuln_para = Paragraph(vuln_name, table_style)
            mitigation_para = Paragraph(mitigation, table_style)
            mitigation_data.append([vuln_para, mitigation_para])

        # Add Nuclei mitigations (limit to first 10)
        for item in nuclei_results[:10]:
            vuln_name = item.get('name', item.get('template', 'Unknown'))[:40]
            mitigation = item.get('mitigation', 'Update software, apply patches, review configuration, and follow security best practices.')
            vuln_para = Paragraph(vuln_name, table_style)
            mitigation_para = Paragraph(mitigation, table_style)
            mitigation_data.append([vuln_para, mitigation_para])

        mitigation_table = Table(mitigation_data, colWidths=[2*inch, 4*inch], repeatRows=1)
        mitigation_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00c9a7')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f1f3f5')]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))

        story.append(mitigation_table)
        story.append(Spacer(1, 20))
    except Exception as e:
        print(f"Error generating mitigations: {e}")
        story.append(Paragraph("Unable to generate AI-powered mitigations. Please consult security documentation.", styles['Normal']))
        story.append(Spacer(1, 20))

    story.append(PageBreak())

    # ZAP Findings
    if zap_results:
        story.append(Paragraph("ZAP Findings (Detailed)", heading_style))

        # Create table data with proper text wrapping
        data = [['Type', 'Severity', 'URL', 'Mitigation']]
        for alert in zap_results:
            # Use Paragraph for text wrapping in cells
            type_text = Paragraph(alert.get('type', '')[:25], table_style)
            severity_text = Paragraph(alert.get('severity', ''), table_style)
            url_text = Paragraph(alert.get('url', '')[:40], table_style)
            mitigation_text = Paragraph(alert.get('mitigation', 'Update software, apply patches, review configuration, and follow security best practices.')[:100], table_style)

            data.append([type_text, severity_text, url_text, mitigation_text])

        # Adjust column widths to fit page
        table = Table(
            data,
            colWidths=[1.2*inch, 0.8*inch, 1.8*inch, 2.2*inch],
            repeatRows=1  # Repeat header on each page
        )

        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2575fc')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f1f3f5')]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))

        story.append(KeepTogether(table))
        story.append(PageBreak())

    # Nuclei Findings
    if nuclei_results:
        story.append(Paragraph("Nuclei Findings (Detailed)", heading_style))

        data2 = [['Template', 'Severity', 'Matched', 'Mitigation']]
        for item in nuclei_results:
            template_text = Paragraph(item.get('template', '')[:25], table_style)
            severity_text = Paragraph(item.get('severity', '').capitalize(), table_style)
            matched_text = Paragraph((item.get('matched', '') or '')[:40], table_style)
            mitigation_text = Paragraph(item.get('mitigation', 'Update software, apply patches, review configuration, and follow security best practices.')[:100], table_style)

            data2.append([template_text, severity_text, matched_text, mitigation_text])

        table2 = Table(
            data2,
            colWidths=[1.2*inch, 0.8*inch, 1.8*inch, 2.2*inch],
            repeatRows=1
        )

        table2.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00c9a7')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))

        story.append(KeepTogether(table2))

    # Footer
    story.append(Spacer(1, 30))
    story.append(Paragraph(
        "Report generated by <b>SecureScanX</b> with AI-powered mitigation recommendations",
        ParagraphStyle('Footer', alignment=TA_CENTER, fontSize=10, textColor=colors.grey)
    ))

    doc.build(story)
    return pdf_path

@app.route('/report/<int:scan_id>')
def report(scan_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM scans WHERE scan_key = ?', (scan_id,))
    row = c.fetchone()
    db.close()

    if not row:
        print(f"No database entry found for scan_id {scan_id}")
        flash('Report not found!')
        return redirect(url_for('dashboard'))

    results = json.loads(row['results'] or '{}')
    print(f"Generating PDF for scan_id {scan_id}: {results}")

    pdf_path = create_pdf_report(scan_id, row, results.get('zap', []), results.get('nuclei', []))
    return send_file(pdf_path, as_attachment=True, download_name=f"SecureScanX_Report_{scan_id}.pdf")

@app.route('/download-json/<int:scan_id>')
def download_json(scan_id):
    """Download scan results as JSON file."""
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM scans WHERE scan_key = ?', (scan_id,))
    row = c.fetchone()
    db.close()

    if not row:
        flash('Scan not found!', 'danger')
        return redirect(url_for('dashboard'))

    # Check if JSON file exists in artifacts directory
    json_path = os.path.join(ARTIFACTS_DIR, f'scan_{scan_id}.json')

    if os.path.exists(json_path):
        # JSON file exists, send it directly
        return send_file(
            json_path,
            as_attachment=True,
            download_name=f"SecureScanX_Scan_{scan_id}.json",
            mimetype='application/json'
        )
    else:
        # JSON file doesn't exist, create it from database
        results = json.loads(row['results'] or '{}')

        # Create comprehensive JSON structure
        scan_data = {
            'scan_id': scan_id,
            'url': row['url'],
            'mode': row['mode'] if 'mode' in row.keys() else 'unknown',
            'timestamp': row['timestamp'],
            'results': {
                'zap': results.get('zap', []),
                'nuclei': results.get('nuclei', []),
                'meta': results.get('meta', {})
            },
            'statistics': {
                'total_vulnerabilities': len(results.get('zap', [])) + len(results.get('nuclei', [])),
                'zap_findings': len(results.get('zap', [])),
                'nuclei_findings': len(results.get('nuclei', []))
            }
        }

        # Save to file
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(scan_data, f, indent=2)

        return send_file(
            json_path,
            as_attachment=True,
            download_name=f"SecureScanX_Scan_{scan_id}.json",
            mimetype='application/json'
        )

# -----------------------
# Background Scheduler for Recurring Scans
# -----------------------
def create_notification(scan_id, url, has_differences, user_id=None):
    """Create a notification for a completed scan"""
    try:
        db = get_db()
        if has_differences:
            message = f"Scheduled scan completed for {url} - Differences found!"
        else:
            message = f"Scheduled scan completed for {url} - No differences detected"

        db.execute('''
            INSERT INTO notifications (scan_id, message, url, has_differences, user_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, message, url, 1 if has_differences else 0, user_id))
        db.commit()
        db.close()
        print(f"Created notification for scan {scan_id}")
    except Exception as e:
        print(f"Error creating notification: {e}")

def run_scheduled_scans():
    """Background thread to check and run scheduled scans"""
    from datetime import datetime, timedelta
    while True:
        try:
            time.sleep(60)  # Check every minute
            db = get_db()
            now = datetime.now()

            # Find scheduled scans that are due
            due_scans = db.execute('''
                SELECT * FROM scheduled_scans
                WHERE enabled = 1 AND (next_run IS NULL OR next_run <= ?)
            ''', (now,)).fetchall()

            for sched in due_scans:
                scan_id = int(time.time())
                scans_status[scan_id] = {'status': 'queued', 'progress': 0, 'results': {}, 'scan_id': scan_id, 'mode': sched['mode'], 'scheduled': True, 'schedule_id': sched['id']}

                # Start scan in background with notification callback
                threading.Thread(target=run_scheduled_scan_with_notification, args=(sched['url'], scan_id, sched['mode'], sched['id'], sched['last_scan_id'], sched['created_by']), daemon=True).start()

                # Update schedule
                next_run = now + timedelta(minutes=sched['interval_minutes'])
                db.execute('''
                    UPDATE scheduled_scans
                    SET last_run = ?, next_run = ?, last_scan_id = ?
                    WHERE id = ?
                ''', (now, next_run, scan_id, sched['id']))
                db.commit()

                print(f"Started scheduled scan {scan_id} for {sched['url']}")

            db.close()
        except Exception as e:
            print(f"Scheduler error: {e}")

def run_scheduled_scan_with_notification(url, scan_id, mode, schedule_id, previous_scan_id, user_id):
    """Run a scheduled scan and create notification after completion"""
    try:
        # Run the scan
        run_scan(url, scan_id, mode)

        # Wait for scan to complete (check status)
        max_wait = 300  # 5 minutes max wait
        waited = 0
        while waited < max_wait:
            status = scans_status.get(scan_id, {}).get('status')
            if status in ['completed', 'error']:
                break
            time.sleep(5)
            waited += 5

        # Compare with previous scan if exists
        has_differences = False
        if previous_scan_id:
            try:
                db = get_db()
                # Get current scan results
                current_row = db.execute('SELECT results FROM scans WHERE scan_key = ?', (scan_id,)).fetchone()
                # Get previous scan results
                previous_row = db.execute('SELECT results FROM scans WHERE scan_key = ?', (previous_scan_id,)).fetchone()
                db.close()

                if current_row and previous_row:
                    current_results = json.loads(current_row['results'] or '{}')
                    previous_results = json.loads(previous_row['results'] or '{}')

                    # Compare results
                    _, new_findings = compare_scans(current_results, previous_results)
                    has_differences = len(new_findings.get('zap', [])) > 0 or len(new_findings.get('nuclei', [])) > 0
            except Exception as e:
                print(f"Error comparing scans: {e}")
        else:
            # First scan, consider it as having findings
            has_differences = True

        # Create notification
        create_notification(scan_id, url, has_differences, user_id)

    except Exception as e:
        print(f"Error in scheduled scan with notification: {e}")

# -----------------------
# Scan Comparison Helper
# -----------------------
def compare_scans(current_results, previous_results):
    """Compare two scan results and identify new vulnerabilities"""
    if not previous_results:
        return current_results, []

    current_vulns = set()
    previous_vulns = set()

    # Create fingerprints for current scan
    for vuln in current_results.get('zap', []):
        fingerprint = f"zap:{vuln.get('type')}:{vuln.get('url')}"
        current_vulns.add(fingerprint)

    for vuln in current_results.get('nuclei', []):
        fingerprint = f"nuclei:{vuln.get('template')}:{vuln.get('matched')}"
        current_vulns.add(fingerprint)

    # Create fingerprints for previous scan
    for vuln in previous_results.get('zap', []):
        fingerprint = f"zap:{vuln.get('type')}:{vuln.get('url')}"
        previous_vulns.add(fingerprint)

    for vuln in previous_results.get('nuclei', []):
        fingerprint = f"nuclei:{vuln.get('template')}:{vuln.get('matched')}"
        previous_vulns.add(fingerprint)

    # Find new vulnerabilities
    new_vulns = current_vulns - previous_vulns

    # Mark new vulnerabilities in current results
    new_findings = {'zap': [], 'nuclei': []}
    for vuln in current_results.get('zap', []):
        fingerprint = f"zap:{vuln.get('type')}:{vuln.get('url')}"
        if fingerprint in new_vulns:
            vuln['is_new'] = True
            new_findings['zap'].append(vuln)

    for vuln in current_results.get('nuclei', []):
        fingerprint = f"nuclei:{vuln.get('template')}:{vuln.get('matched')}"
        if fingerprint in new_vulns:
            vuln['is_new'] = True
            new_findings['nuclei'].append(vuln)

    return current_results, new_findings

# -----------------------
# Entrypoint
# -----------------------
if __name__ == '__main__':
    init_db()

    # Start scheduled scan checker in background
    scheduler_thread = threading.Thread(target=run_scheduled_scans, daemon=True)
    scheduler_thread.start()
    print("Started background scheduler for recurring scans")

    if start_zap_daemon():
        app.run(debug=True, port=5000)
    else:
        print("Failed to start ZAP daemon. Exiting.")
        exit(1)