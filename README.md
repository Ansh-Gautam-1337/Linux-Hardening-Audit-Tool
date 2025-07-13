# 🛡️ Linux Hardening Audit Tool

A **comprehensive security auditing script** for Linux systems designed to assist system administrators in hardening and securing their environments. This tool evaluates the system against a series of critical checks based on **CIS (Center for Internet Security)** benchmarks and best practices.

---

## 📌 Features

- 🔍 **Firewall Audit**: Detects active firewall (UFW, firewalld, or iptables).
- 🚫 **Unused Services Check**: Identifies potentially dangerous or redundant services running.
- 🔐 **SSH Configuration Audit**: Analyzes key security aspects of SSH daemon settings.
- 🗃️ **Critical File Permissions**: Ensures system configuration files have secure ownership and permissions.
- 🧬 **Rootkit Indicators**: Detects tools and kernel modules indicative of potential rootkits.
- 🔑 **Password Policy Review**: Verifies password aging and complexity policies in `/etc/login.defs` and PAM.
- 📝 **Auditd Logging Status**: Ensures system auditing is enabled and persistent across reboots.
- 📊 **Scoring System**: Provides CIS-inspired scoring with a prioritized recommendation list.

---

## 📂 File Structure

```
Linux Hardening Audit Tool/
├── Linux\ Hardening\ Audit\ Tool.py   # Main script
└── README.md                         # This file
```

---

## ⚙️ Requirements

- Python 3.x
- Linux system with `sudo` access
- Optional tools (recommended):
  - `chkrootkit`
  - `rkhunter`

---

## 🛠️ Usage

### ✅ Run Audit (as root):
```bash
sudo python3 "Linux Hardening Audit Tool.py"
```

### 🖥️ Output:
- The script outputs a **colored**, human-readable report to the terminal.
- Includes:
  - Date and OS info
  - Score Summary
  - Detailed Check Results (PASS/WARN/FAIL)
  - Actionable Recommendations

---

## 🔐 What This Tool Checks

| Category                  | Description                                                | CIS Reference       |
|--------------------------|------------------------------------------------------------|---------------------|
| 🔥 Firewall              | UFW, firewalld, or iptables status                         | 3.5.x               |
| 🧹 Unused Services       | Telnet, rsh, rpcbind, avahi, etc.                          | 2.2.x               |
| 🔒 SSH Configuration     | Protocol 2, root login, password auth, etc.                | 5.2.x               |
| 📁 File Permissions      | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, etc.         | 6.1.x               |
| 🕵️ Rootkit Detection     | Checks for promiscuous interfaces and rootkit tools        | -                   |
| 🔑 Password Policies     | PASS_MAX_DAYS, MIN_DAYS, PAM complexity enforcement        | 5.3.x               |
| 📋 Audit Logging         | `auditd` service status                                    | 4.1.x               |

---

## 📈 Example Output Snippet

```
================================================================================
                   Linux Security Audit Report
================================================================================
Date of Audit:       2025-07-13 12:30:45
Operating System:    Ubuntu 22.04 LTS
Hostname:            secure-host

================================================================================
                           Audit Score Summary
================================================================================
Total Score:          87 / 100
Compliance Percentage: 87.00%

================================================================================
                           Prioritized Recommendations
================================================================================
High Priority (FAIL):
  1. Set 'PermitRootLogin no' in sshd_config. (SSH-003)
  2. Disable the following unnecessary services: rlogin.socket, telnet.socket. (SVC-001)
```

---

## 🧩 Design Principles

- **Modular Checks**: Each security check is encapsulated as a function for maintainability.
- **Colorized Output**: Helps distinguish between `PASS`, `WARN`, and `FAIL`.
- **Extendable Framework**: New checks can be added easily.
- **Score-Based Evaluation**: Offers quantitative feedback on system security posture.

---

## 🔒 Why Use This Tool?

Traditional hardening often requires manual inspection of dozens of files and configurations. This tool automates that process:

✅ Saves time  
✅ Standardizes audits  
✅ Improves visibility  
✅ Helps meet compliance

---

## 🧪 Tested On

- Ubuntu 20.04, 22.04
- Debian 11
- CentOS 7, 8
- Rocky Linux 9

> ⚠️ Some checks might vary based on Linux distributions and init systems (e.g., systemd vs init.d)

---
## 🙌 Acknowledgments

- CIS Benchmarks  
- Linux Foundation  
- OWASP Linux Security Project

---

## 📬 Contribute

Pull requests are welcome! If you find bugs or have enhancement suggestions, feel free to open an issue.

---

## 👨‍💻 Author

**Ansh Gautam**  
_Cybersecurity Enthusiast & Developer_

---

> ✨ Feel free to fork, star ⭐, and contribute to help others audit Linux systems more efficiently!
