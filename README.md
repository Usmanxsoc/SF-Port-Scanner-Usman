<div align="center">

# 🔍 SF Port Scanner

### A fast, async port scanner that tells you *what is exposed, how risky it is, and how to fix it*

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-None-2ea44f?style=for-the-badge)
![Async](https://img.shields.io/badge/Built%20with-asyncio-blueviolet?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)

**Open ports are just the start.** This scanner identifies services, checks TLS and HTTP security, rates the risk, and saves a clean report for every scan.

[Quick Start](#-quick-start) • [Features](#-features) • [Screenshots](#-screenshots) • [How It Works](#-how-it-works) • [Responsible Use](#%EF%B8%8F-responsible-use)

</div>

---

> ⚠️ **Only scan systems you own or have written permission to test.** See [Responsible Use](#%EF%B8%8F-responsible-use).

## 📸 Screenshots

<div align="center">

**Live scan in the terminal**

<img src="docs/screenshots/terminal--scan.png" alt="Terminal scan output" width="800">

**Generated HTML report**

<img src="docs/screenshots/html-report.png" alt="HTML report" width="800">

</div>

---

## ✨ Features

| | Feature | What it does |
|---|---|---|
| ⚡ | **Fast async scanning** | Many ports checked at the same time, with adjustable speed, timeout, and retries |
| 🎯 | **Accurate port states** | `open`, `closed`, or `filtered` (no response), not just "open or not" |
| 🌐 | **Flexible targets** | Works with an IP, a domain, or a full URL |
| 🏷️ | **Service detection** | Banner grabbing to identify SSH, FTP, HTTP, SMB, RDP, databases, and more |
| 🔐 | **TLS checks** | Expired, self-signed, or mismatched certificates, and old TLS 1.0 / 1.1 support |
| 🧱 | **HTTP checks** | Missing security headers, version leaks, exposed files like `/.git/HEAD` and `/.env` |
| 🚨 | **Risk analysis** | Findings rated Critical / High / Medium / Low, with a plain-English reason and fix |
| 🧠 | **Honest confidence levels** | Every finding is labeled *Confirmed*, *Likely*, or *Potential*, so nothing is overstated |
| 🗂️ | **Organized reports** | A separate folder for every scan, with `.log`, `.txt`, `.json`, and `.html` outputs |
| 🛡️ | **Built-in safety** | Asks you to confirm you are authorized before every scan |

---

## 🚀 Quick Start

**You only need Python 3.10 or newer.** There is nothing else to install.

```bash
# 1. Download the project
git clone https://github.com/Usmanxsoc/SF-Port-Scanner-Usman.git
cd SF-Port-Scanner-Usman

# 2. Run a scan on your own computer
python main.py 127.0.0.1 1 1024
```

When asked, type `YES` to confirm you are allowed to scan the target.

### More examples

```bash
python main.py                                  # interactive mode (it asks you questions)
python main.py 127.0.0.1 1 1024 --open-only     # show only open ports in the terminal
python main.py example.com 443 443              # check a single port
python main.py scanme.nmap.org 1 1024 --open-only --concurrency 50   # gentle scan of the official test server
```

<details>
<summary><b>⚙️ All options</b></summary>

| Option | Default | Description |
| --- | --- | --- |
| `--timeout` | `2.0` | Seconds to wait for each connection attempt |
| `--retries` | `1` | Extra attempts before a port is called filtered |
| `--concurrency` | `200` | How many ports are checked at the same time |
| `--output-dir` | `scans` | Folder where reports are saved |
| `--open-only` | off | Show only open ports in the terminal (everything is still saved to the log) |
| `--yes` | off | Skip the confirmation prompt (you are confirming you are authorized) |

</details>

---

## 📂 What You Get After Every Scan

Each scan creates its own folder, so results never get mixed up:

```
scans/
└── 127.0.0.1/
    └── 2026-10-02_14-30-00/
        ├── 127.0.0.1_2026-10-02_14-30-00.log   ← every port result + final summary
        ├── summary.txt                          ← easy-to-read summary
        ├── report.json                          ← full data for other tools
        └── report.html                          ← styled report, open in your browser
```

### Port states in plain English

| State | What it means |
| --- | --- |
| 🟢 **Open** | A service is listening and answered |
| 🔴 **Closed** | The machine answered "nothing here" (reachable, but no service) |
| 🟡 **Filtered** | No answer at all, usually a firewall quietly dropping the traffic |

### Example finding

```
[HIGH] SMB service exposed (port 445, Likely)
    Why : SMB has a long history of serious vulnerabilities and worm outbreaks.
    Fix : Never expose SMB to untrusted networks; patch and restrict by firewall.
```

*(Example for illustration.)*

---

## 🔎 What It Checks

<details>
<summary><b>🚪 Risky exposed services</b></summary>

Telnet, FTP, TFTP, SMB, MSRPC, NetBIOS, RDP, VNC, WinRM, an exposed Docker API, and databases such as MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch, and Memcached.

</details>

<details>
<summary><b>🔐 TLS / HTTPS</b></summary>

Expired, self-signed, untrusted, or mismatched certificates; certificates expiring within 30 days; servers that still accept TLS 1.0 or 1.1.

</details>

<details>
<summary><b>🧱 Web server (HTTP)</b></summary>

Version leaks in `Server` and `X-Powered-By`; missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and clickjacking protection; exposed `/.git/HEAD`, `/.env`, phpMyAdmin, and Apache `server-status`. It also avoids false alarms on sites that return "200 OK" for every page.

</details>

<details>
<summary><b>📦 Outdated software banners</b></summary>

A small set of clearly outdated or known-bad versions, such as old OpenSSH, end-of-life Apache, IIS, and PHP, and the backdoored vsFTPd 2.3.4 release.

</details>

### Confidence levels

| Level | Meaning |
| --- | --- |
| ✅ **Confirmed** | Directly observed (for example an expired certificate) |
| 🟠 **Likely** | Based on which port is open |
| ❓ **Potential** | Based on a banner or version text, so it must be verified manually |

---

## 🧩 How It Works

```
Target ➜ Validate & resolve ➜ Confirm authorization ➜ Async port scan
      ➜ Banner + service detection ➜ TLS & HTTP checks
      ➜ Risk rules ➜ Findings with severity ➜ Log + TXT + JSON + HTML report
```

## 🗂️ Project Structure

```
.
├── main.py              # starts the scan, handles logging and reports
└── scanner/
    ├── core.py          # async TCP scanning and port states
    ├── services.py      # service identification and banner grabbing
    ├── tls_http.py      # TLS and HTTP security checks
    ├── risk.py          # risk rules, severity, and scoring
    ├── report.py        # JSON, text, and HTML report writers
    └── utils.py         # target parsing, DNS, and validation helpers
```

---

## 🚧 Limitations

- TCP only (no UDP) and IPv4 only
- Full-connection scan, not a stealth SYN scan, so it is visible in logs
- Banner-based findings are **not proof** of a vulnerability, which is why they are marked *Potential*
- It does not look up CVEs and does not exploit anything
- Results depend on your network. Firewalls, ISPs, and CDNs can change what you see
- If a site sits behind a CDN or hosting platform, you are scanning the provider's servers, not the site owner's

## 🛡️ Responsible Use

This tool is for **learning and authorized security testing only.**

- ✅ Scan your own machine, your own lab, or systems you have **written permission** to test
- ✅ Safe practice targets: `127.0.0.1`, intentionally vulnerable apps you run locally (OWASP Juice Shop, DVWA), and `scanme.nmap.org` (light use only)
- ❌ Do not scan other people's systems, your employer's systems without approval, or third-party infrastructure
- ❌ Do not scan the full 65,535 range against targets you do not control

The author is not responsible for misuse.

## 🗺️ Roadmap

- [ ] Compare two scans and show what changed
- [ ] CVE lookup using the NVD API
- [ ] MITRE ATT&CK mapping for findings
- [ ] Export detection ideas (Sigma-style) for newly exposed services
- [ ] UDP scanning and optional SYN scan
- [ ] Scheduled scans with change alerts
- [ ] Unit tests and CI

## 🤝 Contributing

Ideas, issues, and pull requests are welcome. For bigger changes, please open an issue first.

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### 👤 Author

**Muhammad Usman**

[![GitHub](https://img.shields.io/badge/GitHub-Usmanxsoc-181717?style=for-the-badge&logo=github)](https://github.com/Usmanxsoc)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-muhammad--usman--sf-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/muhammad-usman-sf/)

⭐ If you found this useful, consider giving the repo a star!

</div>
