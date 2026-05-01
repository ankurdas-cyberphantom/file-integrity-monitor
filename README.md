# 🛡️ File Integrity Monitor (FIM)

> A lightweight, CLI-based file integrity monitoring tool built in Python. Detects unauthorized modifications, new files, and deletions using cryptographic hashing — built for security students, sysadmins, and blue teamers.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Category-Blue%20Team%20Tool-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📸 Preview

```
╔══════════════════════════════════════════════╗
║        File Integrity Monitor  v2.0          ║
║        github.com/ankurdas-cyberphantom/fim          ║
╚══════════════════════════════════════════════╝

[*] Checking 3 file(s)...

  ✔ /etc/passwd
  ⚠ [MODIFIED] /etc/hosts
    Old: a3f1c2...
    New: 9b72d4...
  ✖ [DELETED] /var/www/index.php

─── Summary ─────────────────────
  ✔ OK:       1
  ⚠ Modified: 1
  ✚ New:      0
  ✖ Deleted:  1
```

---

## ✨ Features

- **3 Operating Modes** — `baseline`, `check`, `watch`
- **Multiple Hash Algorithms** — MD5, SHA1, SHA256, SHA512
- **Directory Support** — recursively monitors entire folder trees
- **File Metadata Tracking** — size, permissions, last modified time
- **Watch Mode** — continuous real-time monitoring with configurable intervals
- **JSON Reports** — machine-readable output for SIEM integration
- **Colored Terminal Output** — easy-to-read alerts
- **Logging** — persistent log file for audit trails

---

## 🚀 Installation

```bash
git clone https://github.com/ankurdas-cyberphantom/file-integrity-monitor.git
cd file-integrity-monitor
pip install -r requirements.txt
```

**Requirements:** Python 3.10+

---

## 🔧 Usage

### 1. Create a Baseline

```bash
python file_monitor.py --baseline /etc /var/www
```

Creates `fim_db.json` with hashes and metadata for all target files.

### 2. Check for Changes

```bash
python file_monitor.py --check /etc /var/www
```

Compares current state against baseline and prints a color-coded report.

Add `--report` to save results to `fim_report.json`:

```bash
python file_monitor.py --check /etc --report
```

### 3. Continuous Watch Mode

```bash
python file_monitor.py --watch /etc --interval 60
```

Checks every 60 seconds and logs any violations. Press `Ctrl+C` to stop.

---

## 🔑 Options

| Flag | Description | Default |
|------|-------------|---------|
| `--baseline` | Create/update the hash baseline | — |
| `--check` | Check files against baseline | — |
| `--watch` | Continuous monitoring mode | — |
| `--algorithm` | Hash algorithm: `md5`, `sha1`, `sha256`, `sha512` | `sha256` |
| `--db` | Path to baseline database file | `fim_db.json` |
| `--interval` | Watch interval in seconds | `30` |
| `--report` | Save results to `fim_report.json` | off |

---

## 📁 Output Files

| File | Description |
|------|-------------|
| `fim_db.json` | Baseline hash database |
| `fim_report.json` | Last check results (with `--report`) |
| `fim.log` | Persistent audit log |

---

## 🏗️ Project Structure

```
file-integrity-monitor/
├── file_monitor.py     # Main script
├── requirements.txt    # Dependencies
├── .gitignore
├── LICENSE
└── README.md
```

---

## 📖 Use Cases

- Monitor critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/hosts`)
- Watch web server root for defacement detection
- Audit configuration file changes in CI/CD pipelines
- Blue team labs and eJPT/OSCP practice

---

## 🛡️ Disclaimer

This tool is intended for **legal and authorized use only** — on systems you own or have explicit permission to monitor. The author is not responsible for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 🤝 Contributing

Pull requests are welcome. Please open an issue first to discuss what you'd like to change.

---

*Built with 🖤 by [ankurdas-cyberphantom](https://github.com/ankurdas-cyberphantom)*
