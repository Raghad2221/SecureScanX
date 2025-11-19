# SecureScanX - Web Application Security Scanner

A professional-grade web application security scanner that combines **OWASP ZAP** and **Nuclei** to provide comprehensive vulnerability assessments with AI-powered mitigation recommendations.

## Features Implemented

### 1. **Fixed Nuclei Scan Issue** ✅
- Resolved error handling to ensure Nuclei scans complete successfully
- Modified status checking to avoid false errors
- Added better logging for debugging

### 2. **Landing Page** ✅
- Professional landing page with tool description
- Feature highlights and scan mode explanations
- Beautiful gradient animated background
- Direct links to login/register

### 3. **Two-Factor Authentication (2FA)** ✅
- **QR Code Generation**: Admin users get a QR code during registration
- **Google Authenticator Integration**: Scan QR code with Google Authenticator or Authy
- **OTP Verification**: Admin users must enter 6-digit code when logging in
- **Employee Bypass**: Employees login directly without 2FA
- Database schema updated with `totp_secret` and `totp_enabled` columns

### 4. **Enhanced Dashboard Analytics** ✅
- **Vulnerability Overview Chart**: Doughnut chart showing severity distribution
- **Scan Mode Distribution**: Bar chart of scan types used
- **7-Day Scan Trend**: Line chart showing scan activity over time
- Real-time statistics and visual insights

### 5. **Enhanced Report/Detail Section** ✅
- **5 Interactive Charts**:
  - Severity Distribution (Doughnut)
  - Finding Source (ZAP vs Nuclei - Pie)
  - Risk Score Gauge
  - Top Vulnerable Endpoints (Bar)
  - Vulnerability Types (Horizontal Bar)
- Comprehensive visual analytics for each scan

### 6. **Scheduled Scans** ✅
- **Database Schema**: New `scheduled_scans` table
- **UI Interface**: Manage scheduled scans with beautiful interface
- **Interval Options**: 10 min, 15 min, 30 min, 1 hr, 2 hr, 6 hr, 12 hr, 24 hr
- **Pause/Resume**: Toggle scheduled scans on/off
- **Status Tracking**: Last run, next run timestamps

### 7. **Background Scheduler** ✅
- **Automated Execution**: Background thread checks every minute
- **Automatic Scan Triggering**: Runs scans at scheduled intervals
- **Non-Blocking**: Doesn't interfere with manual scans
- **Database Updates**: Tracks last scan ID and next run time

### 8. **Scan Comparison Logic** ✅
- **Vulnerability Fingerprinting**: Creates unique IDs for each finding
- **New Vulnerability Detection**: Compares current vs previous scans
- **Highlighting**: New findings are marked with `is_new` flag
- **Smart Comparison**: Works across both ZAP and Nuclei results

## Installation & Setup

### Prerequisites
- **Python 3.12** or higher
- **OWASP ZAP** (for web scanning)
- **Nuclei** (for CVE/template scanning)
- **Gemini API Key** (for AI-powered mitigations)

### Step 1: Install OWASP ZAP

1. **Download ZAP**:
   - Visit: https://www.zaproxy.org/download/
   - Download the Windows installer (`.exe`)
   - Install to default location: `C:\Program Files\ZAP\Zed Attack Proxy\`

2. **Configure ZAP Path in app.py**:
   - Open `app.py`
   - Find line ~67: `ZAP_PATH = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"`
   - Update the path if you installed ZAP elsewhere

3. **Start ZAP in Daemon Mode**:
   - Open terminal/command prompt
   - Run the command from `command.txt`:
   ```bash
   "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat" -daemon -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
   ```
   - Keep this terminal window open while using SecureScanX
   - ZAP will run in the background on port 8080

### Step 2: Install Nuclei

1. **Download Nuclei**:
   - Visit: https://github.com/projectdiscovery/nuclei/releases
   - Download the Windows binary (`nuclei_*_windows_amd64.zip`)
   - Extract to: `C:\Tools\nuclei\` (create the folder if needed)

2. **Configure Nuclei Path in app.py**:
   - Open `app.py`
   - Find line ~72: `NUCLEI_BIN = r"C:\Tools\nuclei\nuclei.exe"`
   - Update the path if you extracted Nuclei elsewhere

3. **Update Nuclei Templates** (recommended):
   ```bash
   C:\Tools\nuclei\nuclei.exe -update-templates
   ```

### Step 3: Get Gemini API Key

1. **Get API Key**:
   - Visit: https://makersuite.google.com/app/apikey
   - Create a new API key (free tier available)
   - Copy the API key

2. **Configure API Key in gemini_helper.py**:
   - Open `gemini_helper.py`
   - Find line 6: `API_KEY = "AIzaSy..."`
   - Replace with your API key

### Step 4: Install Python Dependencies

1. **Ensure Python 3.12 is installed**:
   ```bash
   python --version
   ```
   - Should show Python 3.12.x or higher
   - Download from https://www.python.org/ if needed

2. **Install requirements**:
   ```bash
   pip install -r requirements.txt
   ```

### Step 5: Run SecureScanX

1. **Start ZAP** (if not already running):
   ```bash
   "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat" -daemon -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
   ```

2. **Run the application**:
   ```bash
   python app.py
   ```

3. **Access the application**:
   - Landing Page: `http://localhost:5000/`
   - Login: `http://localhost:5000/login`
   - Register: `http://localhost:5000/register`

### Quick Setup Checklist

- [ ] Python 3.12+ installed
- [ ] OWASP ZAP downloaded and installed
- [ ] ZAP path configured in `app.py` (line ~67)
- [ ] ZAP running in daemon mode (see command above)
- [ ] Nuclei downloaded and extracted
- [ ] Nuclei path configured in `app.py` (line ~72)
- [ ] Gemini API key obtained
- [ ] API key configured in `gemini_helper.py` (line 6)
- [ ] Dependencies installed via `pip install -r requirements.txt`
- [ ] Application running via `python app.py`

## User Roles

### Admin Users
- **Full Access**: All features available
- **2FA Enabled**: Must use Google Authenticator
- **User Management**: Can add/remove employees
- **QR Code Setup**: Receive QR code during registration

### Employee Users
- **Dashboard Access**: View scans and reports
- **No 2FA**: Direct login without OTP
- **Created by Admins**: Cannot self-register

## Scan Modes

### 1. Normal Mode
- **ZAP Spider + Active Scan**
- Best for: Web applications with forms and authentication
- Duration: ~5-15 minutes

### 2. API Mode (Fast)
- **Nuclei Template Scanning**
- Best for: Quick CVE and misconfiguration checks
- Duration: ~45 seconds (hard timeout)

### 3. Deep Mode
- **ZAP + Nuclei on All URLs**
- Best for: Comprehensive security assessments
- Duration: ~15-30 minutes

## Scheduled Scans

1. **Create Schedule**:
   - Navigate to Dashboard → Scheduled Scans
   - Click "Add Scheduled Scan"
   - Enter URL, select mode and interval
   - Submit

2. **Monitor**:
   - View last run timestamp
   - Check next scheduled run
   - View last scan results

3. **Manage**:
   - Pause/Resume scans
   - Delete schedules
   - Update intervals

## Security Features

- ✅ Password Hashing (PBKDF2-SHA256)
- ✅ Two-Factor Authentication (TOTP)
- ✅ Session Management
- ✅ Role-Based Access Control
- ✅ Input Validation
- ✅ SQL Injection Prevention (Parameterized Queries)

## Architecture

```
SecureScanX
├── app.py                  # Main Flask application
├── user.py                 # User authentication & management
├── templates/              # HTML templates
│   ├── landing.html       # Landing page
│   ├── login.html         # Login page
│   ├── register.html      # Registration page
│   ├── setup_2fa.html     # 2FA QR code setup
│   ├── verify_otp.html    # OTP verification
│   ├── dashboard.html     # Main dashboard with charts
│   ├── index.html         # Scan form
│   ├── status.html        # Scan progress
│   ├── detail.html        # Scan results with 5 charts
│   ├── scheduled_scans.html # Scheduled scans manager
│   └── manage_users.html  # User management
├── scans/                  # Scan artifacts (JSONL, JSON)
├── scans.db               # SQLite database
└── requirements.txt       # Python dependencies
```

## Database Schema

### Users Table
```sql
- id (PRIMARY KEY)
- username (UNIQUE)
- email (UNIQUE)
- password_hash
- company
- role (admin/employee)
- totp_secret (2FA)
- totp_enabled (0/1)
- created_by
- created_at
```

### Scans Table
```sql
- id (PRIMARY KEY)
- scan_key (UNIQUE)
- url
- mode (normal/api/deep)
- timestamp
- results (JSON)
```

### Scheduled Scans Table
```sql
- id (PRIMARY KEY)
- url
- mode
- interval_minutes
- enabled (0/1)
- last_scan_id
- last_run
- next_run
- created_by
- created_at
```

## API Endpoints

### Authentication
- `GET /landing` - Landing page
- `GET /login` - Login page
- `POST /login` - Process login
- `GET /register` - Registration page
- `POST /register` - Process registration with 2FA setup
- `GET /verify-otp` - OTP verification page
- `POST /verify-otp` - Process OTP
- `GET /logout` - Logout

### Scanning
- `GET /scan` - Scan form
- `POST /scan` - Start new scan
- `GET /status/<scan_id>` - Scan status page
- `GET /api/status/<scan_id>` - Scan status JSON
- `GET /detail/<scan_id>` - Scan results with charts
- `POST /delete/<scan_id>` - Delete scan

### Scheduled Scans
- `GET /scheduled` - View scheduled scans
- `POST /scheduled/add` - Create schedule
- `POST /scheduled/delete/<id>` - Delete schedule
- `POST /scheduled/toggle/<id>` - Pause/resume schedule

### Reports
- `GET /report/<scan_id>` - Download PDF report

### User Management
- `GET /dashboard` - Main dashboard
- `GET /manage_users` - Manage employees (admin only)
- `POST /add_user` - Add employee (admin only)
- `POST /delete_user/<id>` - Delete employee (admin only)

## Charts & Visualizations

### Dashboard (3 Charts)
1. **Severity Distribution** - All vulnerabilities by severity
2. **Scan Mode Usage** - Distribution of scan types
3. **7-Day Activity** - Scan frequency trend

### Scan Detail (5 Charts)
1. **Severity Distribution** - Current scan severities
2. **Finding Source** - ZAP vs Nuclei breakdown
3. **Risk Score Gauge** - Calculated risk (0-100)
4. **Top Endpoints** - Most vulnerable URLs
5. **Vulnerability Types** - Category distribution

## Troubleshooting

### Nuclei Scan Not Showing Results

**IMPORTANT:** Nuclei finding zero vulnerabilities is often NORMAL and expected behavior. Here's why:

1. **Nuclei is Template-Based**: It only finds vulnerabilities that match its templates
   - Not a general web app scanner like ZAP
   - Focuses on known CVEs, misconfigurations, and specific vulnerability patterns
   - Your target may simply not have these specific issues

2. **When You'll See Results**:
   - Outdated software with known CVEs (old WordPress, Apache, etc.)
   - Exposed configuration files (.git, .env, debug pages)
   - Known vulnerable endpoints (unpatched APIs)
   - Misconfigurations (CORS, security headers)

3. **Why You Might See Zero Results**:
   - ✅ Target is properly secured and patched (GOOD!)
   - ✅ No exposed sensitive files (GOOD!)
   - ✅ No known CVE matches (GOOD!)
   - Application firewall blocking requests
   - Network/firewall blocking Nuclei probes
   - Target is behind authentication

4. **Debugging Steps**:
   - Check console logs for detailed Nuclei output
   - Verify Nuclei binary path: `C:\Tools\nuclei\nuclei.exe`
   - Update templates: `nuclei -update-templates`
   - Check JSONL file in `scans/` directory
   - Try scanning a known vulnerable target (e.g., DVWA, WebGoat)
   - Test with a simple target like `http://scanme.nmap.org`

5. **Testing Nuclei Installation**:
   ```bash
   # Test Nuclei is working
   C:\Tools\nuclei\nuclei.exe -u http://scanme.nmap.org -t cves/

   # Update templates
   C:\Tools\nuclei\nuclei.exe -update-templates
   ```

### ZAP Not Starting
- Check ZAP installation path
- Ensure port 8080 is available
- Check ZAP API key configuration
- Review console logs for errors

### 2FA Issues
- Ensure device time is synchronized
- Use 1-minute window for OTP validation
- Keep backup of secret key
- Try re-scanning QR code

## Future Enhancements

- Email notifications for new vulnerabilities
- Webhook integrations
- Multi-target scanning
- Custom vulnerability rules
- Advanced reporting templates
- API-only mode for CI/CD integration

## Support

For issues and feature requests, please check:
- Console logs for errors
- Database integrity
- External tool availability (ZAP, Nuclei)

## License

This tool is for educational and authorized security testing only. Always obtain proper authorization before scanning any web application.

---

**Built with Flask, OWASP ZAP, Nuclei, and Chart.js**
