# 🛡️ NetSpecter — Lightweight IDS/IPS for Raspberry Pi

**English** | [Türkçe](README.tr.md)

NetSpecter is a real-time **Intrusion Detection & Prevention System (IDS/IPS)** built for the Raspberry Pi (and any Debian/Ubuntu-based Linux host). It combines the **Suricata** inspection engine with a Python decision layer that classifies alerts and automatically blocks attackers using **iptables / ip6tables**. Every event is stored in **MySQL / MariaDB** and surfaced through a live **web dashboard**, a colored **terminal event stream**, **Telegram notifications**, and downloadable **PDF reports**.

> Developed as part of a graduation thesis project.

---

## 📋 Table of Contents

- [Features](#-features)
- [How It Works](#-how-it-works)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Web Dashboard](#-web-dashboard)
- [Telegram Notifications](#-telegram-notifications)
- [PDF & JSON Reports](#-pdf--json-reports)
- [Configuration](#-configuration)
- [Detection & Response Rules](#-detection--response-rules)
- [Database Schema](#-database-schema)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Troubleshooting](#-troubleshooting)
- [Security Notes](#-security-notes)
- [License](#-license)

---

## ✨ Features

| | Feature | Details |
|---|---|---|
| 🔍 | **Real-time detection** | Suricata with the Emerging Threats ruleset (48,000+ rules) inspects live network traffic |
| 🧠 | **Unified classification** | Signatures, categories, and ports are mapped to 9 attack classes (`nmap_scan`, `brute_force_*`, `dos_attack`, `exploit`, `malware`, `web_attack`, `info_leak`) |
| 🚫 | **Automatic IPv4 & IPv6 blocking** | Offending IPs are logged and dropped in a dedicated `IDS_IPS` chain (`iptables` + `ip6tables`) with duplicate-rule prevention |
| ⏱️ | **Threshold & duration logic** | Brute-force classes require N alerts within a time window before blocking; supports both manual-unblock persistence and timed expiration |
| 🧾 | **Protocol anomaly blocking** | Suricata `applayer`, `decode`, and `stream` anomalies trigger automatic blocks |
| 🛡️ | **Two-level whitelist** | Static whitelist in `config.py` + live dynamic whitelist in MySQL (managed via Dashboard or CLI) |
| 💾 | **Persistent state** | Alerts, blocks, and whitelist entries are stored in MySQL/MariaDB and re-applied on service startup |
| 📊 | **Web dashboard** | Flask + Socket.IO: live alert feed, attack distribution chart, 24h timeline, one-click unblock, and whitelist management |
| 🔐 | **Hardened authentication** | Salted `PBKDF2-HMAC-SHA256` (200k iterations) password hashes, login rate-limiting, `HttpOnly`/`SameSite=Lax` sessions |
| 🌐 | **TR / EN interface** | Instant Turkish / English language switcher on the login and dashboard pages |
| 📱 | **Telegram bot** | Real-time alerts for high-severity events (`sev 1–2`) and coordinated DDoS attacks (with per-IP cooldown) |
| 📄 | **PDF & JSON reports** | One-click daily security summary PDF, per-IP forensic PDF report, and hourly JSON snapshots |
| 🖥️ | **One-command launch** | `sudo netspecter` starts the service, dashboard, and Telegram bot, then attaches to a live colored event stream |
| ♻️ | **Self-maintenance** | Automatic Suricata rule updates every 24h (`SIGUSR2` live reload), process watchdog, DB sync every 10s, and logrotate |

---

## 🏗️ How It Works

```
                         ┌────────────────────────┐
                         │     sudo netspecter    │  (netspecter_cli.py)
                         └───┬─────────┬────────┬─┘
                             │         │        │
             systemd service │         │        │ background processes
                             ▼         ▼        ▼
┌───────────────────────────────┐ ┌──────────┐ ┌──────────────┐
│ ids_ips.py  (orchestrator)    │ │dashboard │ │ telegram_bot │
│  ├─ starts & watches Suricata │ │  .py     │ │     .py      │
│  ├─ monitor.py  (classifier)  │ │ :5000    │ │              │
│  ├─ blocker.py  (ip[6]tables) │ └────┬─────┘ └──────┬───────┘
│  └─ periodic jobs & DB sync   │      │              │
└──────┬─────────────────┬──────┘      │              │
       │ tail            │ read/write  │ tail + R/W   │ tail
       ▼                 ▼             ▼              ▼
┌──────────────────┐  ┌───────────────────────┐  ┌──────────────────┐
│ Suricata         │  │ MySQL  (netspecter)   │  │ Telegram Bot API │
│ eve.json         │  │ alerts / blocked_ips  │  └──────────────────┘
│ ← network traffic│  │ whitelist / users     │
└──────────────────┘  └───────────────────────┘
       │
       ▼
iptables / ip6tables  INPUT & FORWARD ──► IDS_IPS chain ──► LOG + DROP <attacker-ip>
```

### Pipeline of a single alert

1. **Capture:** Suricata inspects packets on the configured interface and appends JSON events to `/var/log/suricata/eve.json`.
2. **Filter & Classify:** `monitor.py` tails `eve.json` (handling log rotation), filters out benign noisy signatures, and classifies the alert using `classify()`.
3. **Persist Alert:** The classified alert is saved to the MySQL `alerts` table.
4. **Evaluate Policy:** If the class action is `block` (or Suricata severity is `1` or `2`), `monitor.py` checks whether the per-IP sliding-window threshold has been reached.
5. **Enforce Block:** `blocker.py` checks both the static (`config.py`) and dynamic (MySQL) whitelists, inserts idempotent `LOG` + `DROP` rules at the top of the `IDS_IPS` chain (`iptables` for IPv4, `ip6tables` for IPv6), and records the block in `blocked_ips`.
6. **Notify & Visualize:** `dashboard.py` streams the event over Socket.IO to connected browsers, while `telegram_bot.py` evaluates DDoS and high-severity notification rules.

### Background jobs inside `ids_ips.py`

| Job | Interval | Purpose |
|---|---|---|
| **Rule update** | 24 h | Runs `suricata-update` and reloads rules live via `SIGUSR2` |
| **Periodic report** | 1 h | Writes a JSON statistics snapshot to `/var/log/netspecter/reports/` |
| **Block cleanup** | 60 s | Removes expired temporary blocks when timed mode is enabled |
| **DB sync** | 10 s | Syncs blocks added or removed via the Web Dashboard or `netspecter-manager` |
| **Watchdog** | 10 s | Automatically restarts Suricata if the process exits unexpectedly |

---

## 📦 Requirements

**Hardware / OS**
- Raspberry Pi 3 / 4 / 5 (or any Debian / Ubuntu Linux host)
- Raspberry Pi OS / Debian 12+ or Ubuntu 22.04+
- Root privileges (`sudo`)

**Software (automatically installed by `install.sh`)**
| Component | Version / Note |
|---|---|
| Python | 3.10+ |
| Suricata | 7.x + `suricata-update` |
| Firewall | `iptables` (and `ip6tables` for IPv6) |
| Database | MariaDB / MySQL (`mariadb-server`) |
| Python packages | `flask`, `flask-socketio`, `requests`, `mysqlclient`, `reportlab` |
| System fonts | `fonts-dejavu-core` (for Turkish characters in PDF reports) |

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/DrXendria/NetSpecter.git
cd NetSpecter
```

### 2. Configure environment variables (optional before install)

```bash
cp .env.example .env
nano .env
```

```env
# Telegram (optional - the bot is skipped if these are missing)
TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
TELEGRAM_CHAT_ID=123456789

# DDoS detection & notification tuning
DDOS_TIME_WINDOW=60
DDOS_MIN_IPS=10
NOTIFY_COOLDOWN=300

# MySQL (install.sh auto-generates a strong password if left as CHANGE_ME)
DB_HOST=localhost
DB_PORT=3306
DB_NAME=netspecter
DB_USER=netspecter
DB_PASSWORD=CHANGE_ME

# Web Dashboard (install.sh auto-generates a password if left empty/CHANGE_ME)
DASHBOARD_ADMIN_PASSWORD=CHANGE_ME
FLASK_SECRET_KEY=
```

### 3. Run the automated installer

```bash
sudo bash install.sh
```

`install.sh` performs a complete setup:
1. Installs system packages (`suricata`, `suricata-update`, `iptables`, `mariadb-server`, build headers, and `fonts-dejavu-core`).
2. Copies all application files, templates, and `.env` to **`/opt/netspecter/`** (with `chmod 600 /opt/netspecter/.env`).
3. Auto-detects the default network interface (e.g. `eth0` or `wlan0`) and updates `/opt/netspecter/config.py`.
4. Enables `eve-log` (`eve.json`) in `/etc/suricata/suricata.yaml`, downloads Emerging Threats rules (`suricata-update`), and validates the config.
5. Installs Python dependencies (`flask`, `flask-socketio`, `requests`, `mysqlclient`, `reportlab`).
6. Starts MariaDB, provisions the `netspecter` database and user, generates random credentials if needed, and initializes all tables via `database.py`.
7. Registers and enables **`netspecter.service`** (systemd), installs **`netspecter`** and **`netspecter-manager`** in `/usr/local/bin`, and configures `logrotate`.

> [!IMPORTANT]
> At the end of installation, `install.sh` prints the generated **Dashboard `admin` password** (also saved in `/opt/netspecter/.env` as `DASHBOARD_ADMIN_PASSWORD`).

### 4. Whitelist your management IP ⚠️

Before starting the system on a remote machine, add your own IP to the whitelist so you never lock yourself out during testing:

```bash
sudo netspecter-manager whitelist-add 192.168.1.10 --description "My workstation"
```

Or add it to the static whitelist in `/opt/netspecter/config.py`.

### 5. Verify the installation

```bash
cd /opt/netspecter
sudo python3 test_system.py
```

---

## 🖥️ Usage

### Start everything with one command

```bash
sudo netspecter
```

This command:
1. Cleans up any stale dashboard or Telegram bot processes,
2. Starts (or restarts) the **`netspecter`** systemd service,
3. Starts the **Web Dashboard** in the background on port `5000`,
4. Starts the **Telegram Bot** in the background (if configured in `/opt/netspecter/.env`),
5. Opens a **live, color-coded event stream** in your terminal.

Press `Ctrl+C` at any time to exit the log viewer — the background services continue running.

### Service management (systemd)

```bash
sudo systemctl start   netspecter
sudo systemctl stop    netspecter
sudo systemctl restart netspecter
sudo systemctl status  netspecter
sudo journalctl -u netspecter -f        # raw service logs
```

### Admin CLI (`netspecter-manager`)

`netspecter-manager` reads and writes directly to MySQL and `iptables`/`ip6tables`. Any change is picked up by the running service within ~10 seconds:

```bash
sudo netspecter-manager list                                              # list active blocked IPs
sudo netspecter-manager stats                                             # alert & block statistics
sudo netspecter-manager iptables                                          # inspect IDS_IPS chains (v4 & v6)
sudo netspecter-manager block 203.0.113.5 --reason "Manual" --permanent   # permanent manual block
sudo netspecter-manager block 203.0.113.5 --duration 3600                 # timed manual block (seconds)
sudo netspecter-manager unblock 203.0.113.5                               # remove block (iptables + DB)
sudo netspecter-manager whitelist                                         # list static & DB whitelist
sudo netspecter-manager whitelist-add 192.168.1.10 --description "Admin"  # add IP to DB whitelist
sudo netspecter-manager whitelist-remove 192.168.1.10                     # remove IP from DB whitelist
sudo netspecter-manager test                                              # inject a test Nmap alert into eve.json
```

### IDS-only (monitoring) mode

To run in passive detection mode without modifying firewall rules, set `'enabled': False` under `blocking` in `/opt/netspecter/config.py` and restart the service.

---

## 🌐 Web Dashboard

Open in your browser:

```
http://<raspberry-pi-ip>:5000
```

- **Login:** `admin` + the password in `/opt/netspecter/.env` (`DASHBOARD_ADMIN_PASSWORD`, or `netspecter` if initialized manually without `.env`).
- **Account settings:** Change your username or password anytime at `/settings`.
- **Capabilities:**
  - Real-time alert stream via Socket.IO (attack badge, source IP, destination port, severity, signature, and one-click IP report icon 📄)
  - Attack-type distribution (doughnut chart) & 24-hour alert timeline
  - Active blocked IPs list with one-click **Unblock**
  - Dynamic **Whitelist** management (add/remove IPs with descriptions)
  - One-click **Daily Security Summary PDF** download
  - Instant **TR / EN** language toggle

<details>
<summary><b>REST API & Socket.IO Reference</b></summary>

| Method | Endpoint | Description |
|---|---|---|
| `GET` / `POST` | `/login` | Login page / JSON auth `{username, password}` (rate-limited: 5 fails / 5 min) |
| `GET` | `/logout` | Clear session |
| `GET` | `/` | Main dashboard UI |
| `GET` | `/settings` | Account settings UI |
| `POST` | `/api/settings/change-password` | `{old_password, new_password}` (min 8 chars) |
| `POST` | `/api/settings/change-username` | `{new_username, password}` |
| `GET` | `/api/stats` | Summary metrics, 24h distribution, timeline, whitelist count |
| `GET` | `/api/alerts` | Latest 200 alerts |
| `GET` | `/api/timeline` | Minute-by-minute alert counts (last 24h) |
| `GET` | `/api/blocked` | Currently blocked IPs |
| `POST` | `/api/unblock/<ip>` | Unblock an IPv4/IPv6 address |
| `GET` / `POST` | `/api/whitelist` | List whitelist / add `{ip, description}` |
| `DELETE` | `/api/whitelist/<ip>` | Remove IP from whitelist |
| `GET` | `/api/report/daily` | Generate & download daily PDF report |
| `GET` | `/api/report/ip/<ip>` | Generate & download per-IP forensic PDF report |

**Socket.IO server-to-client events:** `new_alert`, `blocked_update`, `stats_update`.
</details>

---

## 📱 Telegram Notifications

### Setup

1. Message **@BotFather** on Telegram → `/newbot` → copy the HTTP API token.
2. Message **@userinfobot** → copy your numeric Chat ID.
3. Add both to `/opt/netspecter/.env`:
   ```env
   TELEGRAM_BOT_TOKEN=1234567890:ABCdef...
   TELEGRAM_CHAT_ID=123456789
   ```
4. Run `sudo netspecter` — the bot verifies connectivity on startup and sends a **"NetSpecter Bot Active"** message.

### Notification triggers

| Trigger | Condition |
|---|---|
| 🚨 **Possible DDoS** | `DDOS_MIN_IPS` (default `10`) distinct source IPs trigger the same attack category within `DDOS_TIME_WINDOW` (default `60` s) |
| 🔴 **Critical Alert** | Suricata `severity = 1` |
| 🟠 **High Alert** | Suricata `severity = 2` |

To prevent alert fatigue, notifications for the same source IP (or the same DDoS category) are rate-limited by `NOTIFY_COOLDOWN` (default `300` seconds).

---

## 📄 PDF & JSON Reports

Reports are generated by `reporter.py` (using ReportLab with DejaVu Sans for full UTF-8 / Turkish character support) and stored in `/var/log/netspecter/reports/`:

| Report Type | Format | Contents | Trigger |
|---|---|---|---|
| **Daily Security Summary** | PDF | Total 24h alerts, newly blocked IPs today, top 5 offending source IPs | Dashboard button (`/api/report/daily`) |
| **Per-IP Forensic Report** | PDF | Total alerts & blocks for the IP, table of the last 40 alerts (timestamp, attack type, target port, severity) | 📄 button next to an alert (`/api/report/ip/<ip>`) |
| **Periodic Snapshot** | JSON | Timestamped blocker & alert counters | Every hour (`report_interval`) & on service shutdown |

---

## ⚙️ Configuration

### `/opt/netspecter/config.py`

| Key | Default | Description |
|---|---|---|
| `suricata.config_path` | `/etc/suricata/suricata.yaml` | Path to Suricata YAML config |
| `suricata.eve_log` | `/var/log/suricata/eve.json` | Suricata EVE JSON output file |
| `suricata.interface` | Auto-detected (`eth0`/`wlan0`) | Network interface monitored by Suricata |
| `blocking.enabled` | `True` | `True` = IPS mode (blocks via iptables); `False` = IDS-only mode |
| `blocking.block_duration` | `3600` | Default block duration in seconds (when timed mode is active) |
| `blocking.permanent_block_threshold` | `5` | Number of violations before an IP is permanently blocked |
| `blocking.persist_until_manual_unblock` | `True` | `True` = keep all blocks active until manually unblocked in Dashboard/CLI; `False` = automatically expire blocks after their signature duration |
| `blocking.whitelist` | `['127.0.0.1', '::1']` | Static whitelist (supplemented by the MySQL whitelist) |
| `rule_update_interval` | `86400` | Suricata rule update interval (24h) |
| `report_interval` | `3600` | Periodic JSON report interval (1h) |
| `cleanup_interval` | `60` | Expired block cleanup interval (60s) |
| `reports.output_dir` | `/var/log/netspecter/reports` | Directory for generated PDF and JSON reports |

---

## 🎯 Detection & Response Rules

`monitor.py` classifies Suricata alerts by matching signatures and categories (with word-boundary protection for short acronyms like `RCE`, `DoS`, `LFI`, `C2`), falling back to destination port (`22` → SSH, `21` → FTP, `80/443/8080/8443` → Web) if needed:

| Class | Example Signatures / Tools | Action | Threshold | Duration* |
|---|---|---|---|---|
| `brute_force_ssh` | SSH scan/brute, invalid user, banner mismatch (Hydra, Medusa) | Block | 3 alerts / 60 s | 2 hours |
| `brute_force_ftp` | FTP brute/login failures, anonymous FTP | Block | 3 alerts / 60 s | 2 hours |
| `brute_force_http` | HTTP/web brute, credential stuffing, password spray, Hydra | Block | 5 alerts / 60 s | 1 hour |
| `malware` | `ET MALWARE`, `ET TROJAN`, C2, botnet, backdoor, ransomware, rootkit | Block | Immediate | Permanent |
| `exploit` | `ET EXPLOIT`, RCE, `CVE-*`, SQLi, command injection, path traversal, LFI/RFI, SSRF, XXE | Block | Immediate | 24 hours |
| `dos_attack` | `ET DOS`, SYN/UDP/ICMP/HTTP flood, Denial of Service | Block | Immediate | 24 hours |
| `web_attack` | `ET WEB_SERVER`, XSS, CSRF, web shell, Nikto, sqlmap, gobuster, ffuf, wpscan, Burp, ZAP, Nessus | Block | Immediate | 1 hour |
| `nmap_scan` | `ET SCAN`, Nmap, Masscan, ZMap, SYN/NULL/XMAS/FIN/ACK/UDP scans | Block | Immediate | 1 hour |
| `info_leak` | `ET INFO`, `ET HUNTING`, `ET POLICY`, reconnaissance | Log only** | — | — |
| Protocol anomaly | Suricata `applayer`, `decode`, or `stream` anomaly events | Block | Immediate | 30 minutes |

\* When `persist_until_manual_unblock` is `True` (default), blocks remain active until manually removed via the Dashboard or CLI. Set `persist_until_manual_unblock: False` in `config.py` to enforce the per-class durations above.  
\** Any alert with Suricata `severity <= 2` is blocked even if its class defaults to `log`.

---

## 🗄️ Database Schema

Managed automatically by `database.py` (`init_db()` runs on startup and migrates existing tables):

| Table | Purpose | Key Columns |
|---|---|---|
| `users` | Dashboard accounts | `id`, `username`, `password_hash` (`pbkdf2_sha256$...`), `salt`, `created_at` |
| `alerts` | Historical alert log | `id`, `src_ip`, `dest_port`, `attack_type`, `severity`, `signature`, `category`, `created_at` |
| `blocked_ips` | Active & past blocks | `id`, `ip`, `reason`, `attack_type`, `permanent`, `expires_at`, `blocked_at`, `unblocked_at` |
| `whitelist` | Dynamic IP whitelist | `id`, `ip` (unique), `description`, `added_at` |
| `ddos_events` | Detected DDoS bursts | `id`, `attack_type`, `ip_count`, `time_window`, `sample_ips`, `detected_at` |

---

## 📁 Project Structure

```
NetSpecter/
├── ids_ips.py          # Main orchestrator: iptables init, Suricata lifecycle, watchdog, background threads
├── monitor.py          # eve.json tailer, unified alert classifier, sliding-window thresholds
├── blocker.py          # iptables / ip6tables IDS_IPS chain manager, whitelist check, DB sync
├── database.py         # MySQL/MariaDB layer: schema & migrations, PBKDF2 auth, queries
├── config.py           # Central configuration
├── dashboard.py        # Flask + Socket.IO web dashboard & REST API
├── telegram_bot.py     # Telegram notification bot (high-severity alerts + DDoS detector)
├── reporter.py         # ReportLab PDF generator (daily & per-IP) + JSON reports
├── netspecter_cli.py   # `sudo netspecter` CLI launcher & live colored event viewer
├── manager.py          # `sudo netspecter-manager` administrative CLI
├── test_system.py      # Automated system self-test suite
├── install.sh          # One-step installer (packages, Suricata, MariaDB, systemd, logrotate)
├── .env.example        # Environment variables template
├── LICENSE             # MIT License
├── README.md           # English documentation
├── README.tr.md        # Turkish documentation
└── templates/
    ├── dashboard.html  # Real-time dashboard UI (TR / EN)
    ├── login.html      # Login page (TR / EN)
    └── settings.html   # Account settings page
```

---

## 🧪 Testing

### 1. Automated self-test

```bash
sudo python3 /opt/netspecter/test_system.py
```

Verifies root privileges, Suricata binary & `eve.json` configuration, `IDS_IPS` chain setup, Python module imports, live `IPBlocker` block/unblock rule insertion and cleanup, and an end-to-end simulated Nmap alert through `AlertMonitor`.

### 2. Simulated alert injection

```bash
sudo netspecter-manager test
```

Appends a synthetic Nmap alert (`192.168.100.200`) to `/var/log/suricata/eve.json`. Within a second, you will see the block appear in `sudo netspecter` and on the Web Dashboard. Remove it afterwards with:

```bash
sudo netspecter-manager unblock 192.168.100.200
```

### 3. Live network testing (from a separate non-whitelisted host)

```bash
nmap -sS -sV <raspberry-pi-ip>                         # Port scan
nikto -h http://<raspberry-pi-ip>:5000                 # Web scanner
hydra -l root -P passwords.txt ssh://<raspberry-pi-ip> # SSH brute force
```

> ⚠️ Only run active scans against networks and hosts you own or have explicit permission to test.

---

## 🩺 Troubleshooting

| Symptom | Resolution |
|---|---|
| No alerts are detected | Verify `suricata.interface` in `/opt/netspecter/config.py` matches `ip route show default`, then test with `sudo suricata -T -c /etc/suricata/suricata.yaml -i <iface>` |
| `eve.json` is not created | Check `sudo journalctl -u netspecter -n 50` and ensure `suricata-update` has downloaded rules |
| Locked out of SSH / Dashboard | From the local Pi console, run `sudo iptables -F IDS_IPS` (and `sudo netspecter-manager unblock <your-ip>`), then add your IP via `sudo netspecter-manager whitelist-add <your-ip>` |
| Database connection error | Check `sudo systemctl status mariadb` and confirm `DB_*` credentials in `/opt/netspecter/.env` |
| Turkish characters broken in PDF | Install DejaVu fonts: `sudo apt install -y fonts-dejavu-core` |
| Telegram bot does not start | Ensure `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set in `/opt/netspecter/.env`; test directly with `sudo python3 /opt/netspecter/telegram_bot.py` |

---

## 🔒 Security Notes

- **Never commit `.env`:** Keep `/opt/netspecter/.env` (and any local `.env`) out of version control (`chmod 600`). If a token or password was ever pushed to git history, revoke/rotate it immediately (e.g. via `@BotFather` → `/revoke`) and remove `.env` from tracking (`git rm --cached .env`).
- **Whitelist your workstation:** Always add your management IP to the whitelist before testing attacks.
- **Restrict dashboard exposure:** The Flask-SocketIO server on port `5000` is intended for LAN / management network access. If you need remote access, place it behind a VPN (e.g. WireGuard) or an HTTPS reverse proxy (Nginx/Caddy).

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
