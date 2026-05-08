# PhantomAI

```
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗ █████╗ ██╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║███████║██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██║██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
  AI-Powered Penetration Testing Framework  |  OWASP 2025  |  v1.0
```

**PhantomAI** is an AI-powered, automated penetration testing framework that covers the full **OWASP Top 10 (2025)** attack surface. It uses **Claude Haiku** for cheap triage and classification tasks, and **Claude Sonnet** for deep reasoning — generating context-aware payloads, filtering false positives, and producing professional HTML reports — all for under **$0.01 per scan**.

> **For authorized security testing only.** Always obtain written permission before testing any target.

---

## Table of Contents

- [Features](#features)
- [OWASP 2025 Coverage](#owasp-2025-coverage)
- [AI Integration](#ai-integration)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scan Phases](#scan-phases)
- [Output & Reports](#output--reports)
- [Cost Breakdown](#cost-breakdown)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

- **Full 6-phase pentest pipeline** — recon → enumeration → vuln analysis → exploitation → reporting
- **OWASP 2025 Top 10** coverage across all phases with per-finding categorization
- **AI-powered at every phase** — tech stack fingerprinting, URL prioritization, false positive triage, context-aware payload generation, executive reporting
- **GET + POST exploitation** — discovers and tests HTML form fields automatically, not just query parameters
- **SSTI-safe detection** — uses unique computed markers (`{{523*523}}=273529`) instead of generic numbers that cause false positives
- **Response diffing** — compares baseline vs. payload response (status code + body length + content) for reliable detection
- **AI-generated HTML report** — dark-themed, professional output with OWASP badges, CWE IDs, CVSS scores, evidence blocks, and stack-specific remediation
- **Graceful `--no-ai` mode** — full scan with fallback logic when no API key is set
- **Cost-optimized** — Haiku for cheap tasks, Sonnet only where depth matters, prompt caching on all system prompts

---

## OWASP 2025 Coverage

| ID  | Category                            | Coverage | Tools / Method                            |
|-----|-------------------------------------|----------|-------------------------------------------|
| A01 | Broken Access Control               | Good     | Nuclei templates + AI triage              |
| A02 | Cryptographic Failures              | Added    | sslyze TLS/SSL scan                       |
| A03 | Injection (SQLi, XSS, SSTI, CMDi)  | Good     | SQLMap + Dalfox + AI payloads (GET+POST)  |
| A04 | Insecure Design                     | Partial  | AI inference from stack + findings        |
| A05 | Security Misconfiguration           | Good     | Nuclei templates + AI triage              |
| A06 | Vulnerable & Outdated Components    | Partial  | Nuclei CVE templates                      |
| A07 | Auth & Identification Failures      | Added    | ffuf auth endpoint discovery              |
| A08 | Software & Data Integrity Failures  | Partial  | Nuclei templates                          |
| A09 | Security Logging Failures           | Partial  | AI inference from response patterns       |
| A10 | Server-Side Request Forgery (SSRF)  | Added    | Custom SSRF probes (metadata endpoints)   |

---

## AI Integration

PhantomAI uses the **Anthropic Claude API** with two models routed by task complexity:

| Model | Used For | Cost (approx.) |
|---|---|---|
| `claude-haiku-4-5` | Tech fingerprinting, URL scoring, wordlist hints, false positive triage | ~$0.00025 per call |
| `claude-sonnet-4-6` | Context-aware payload generation, OWASP-mapped report with CVSS/CWE | ~$0.0045 per call |

### AI Touchpoints (per scan)

| Phase | AI Task | Model |
|---|---|---|
| Phase 0 | Identify framework, CMS, WAF, server from HTTP headers + HTML | Haiku |
| Phase 1 | Score and prioritize top 50 attack-surface URLs from 500+ discovered | Haiku |
| Phase 2 | Suggest stack-specific directory paths to add to ffuf wordlist | Haiku |
| Phase 3 | Triage nuclei/dalfox/sqlmap/sslyze output — remove false positives | Haiku |
| Phase 4 | Generate context-aware payloads per parameter name and detected stack | Sonnet |
| Phase 5 | Write OWASP-mapped report with executive summary, CVSS, remediation | Sonnet |

### Cost Controls

- **Prompt caching** (`cache_control: ephemeral`) on all system prompts — up to 90% cost reduction on repeat calls
- All tool output **truncated to 3000 chars** before any API call
- AI calls are **skipped entirely** when a phase returns empty results
- `--no-ai` flag disables all API calls — tool works fully offline with fallback logic
- **Haiku handles 4 of 6 calls** (12× cheaper than Sonnet)

**Estimated total cost per full scan: ~$0.008**

---

## Project Structure

```
PhantomAI/
│
├── phantomai.py                        # Main entry point (run this)
├── main.py                             # Backward-compat shim → calls phantomai.py
├── requirements.txt                    # Python dependencies
├── .env.example                        # Environment variable template
│
├── core/
│   ├── ai_engine.py                    # Claude client (Haiku + Sonnet, caching, fallback)
│   ├── owasp_mapper.py                 # OWASP 2025 Top 10 category + CWE mapping
│   ├── run_cmd.py                      # Shared safe subprocess utility (no shell=True)
│   ├── tech_fingerprint.py             # HTTP header + HTML stack detection
│   ├── input/
│   │   └── target_handler.py           # Target normalization
│   └── validation/
│       ├── web_check.py                # HTTP/HTTPS reachability
│       └── network_check.py            # Ping + nmap reachability
│
├── pipelines/
│   ├── phase0_init.py                  # Target validation + tech fingerprinting
│   ├── recon/
│   │   └── recon_pipeline.py           # subfinder + assetfinder + amass + gau + waybackurls
│   ├── enumeration/
│   │   └── enum_pipeline.py            # ffuf directory fuzzing + param extraction
│   ├── vuln_analysis/
│   │   └── vuln_pipeline.py            # nuclei + dalfox + sqlmap + sslyze + SSRF probes
│   ├── exploitation/
│   │   └── exploit_pipeline.py         # GET + POST payload testing with response diffing
│   └── post_exploitation/
│       └── post_pipeline.py            # AI report synthesis
│
├── reports/
│   ├── html_reporter.py                # Jinja2 report renderer
│   └── template.html                   # Dark-themed HTML report template
│
└── wordlists/
    └── dirs.txt                        # Bundled directory wordlist (160+ paths)
```

---

## Prerequisites

### Python
- Python **3.10 or higher** (uses `match`, `type unions`, `list[str]` hints)

### External Tools
PhantomAI orchestrates these tools — they must be installed and available in your `PATH`:

| Tool | Purpose | Install |
|---|---|---|
| `subfinder` | Subdomain enumeration | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| `assetfinder` | Asset discovery | [tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) |
| `amass` | Subdomain enumeration | [owasp-amass/amass](https://github.com/owasp-amass/amass) |
| `httpx` | Live host detection | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| `gau` | URL gathering (GAU) | [lc/gau](https://github.com/lc/gau) |
| `waybackurls` | Wayback Machine URLs | [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) |
| `ffuf` | Directory + auth fuzzing | [ffuf/ffuf](https://github.com/ffuf/ffuf) |
| `nuclei` | Template-based vuln scanner | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| `dalfox` | XSS scanner | [hahwul/dalfox](https://github.com/hahwul/dalfox) |
| `sqlmap` | SQL injection scanner | [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) |
| `sslyze` | TLS/SSL scanner | `pip install sslyze` |
| `curl` | HTTP requests (SSRF probes) | Pre-installed on most systems |
| `nmap` | Port scanning | [nmap.org](https://nmap.org/download.html) |

> **Tip:** Most Go-based tools (subfinder, httpx, ffuf, nuclei, dalfox, gau, waybackurls, assetfinder) can be bulk-installed using [pdtm](https://github.com/projectdiscovery/pdtm) — Project Discovery's tool manager.

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/Minionik/PhantomAI.git
cd PhantomAI
```

### Step 2 — Create a virtual environment (recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `anthropic` — Claude API SDK
- `jinja2` — HTML report rendering
- `requests` — HTTP requests for fingerprinting + exploitation
- `python-dotenv` — `.env` file loading

### Step 4 — Install external tools

**On Linux/macOS (recommended method using pdtm):**
```bash
# Install pdtm (Project Discovery tool manager)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

# Install all Project Discovery tools at once
pdtm -install subfinder httpx nuclei dalfox ffuf gau

# Install remaining tools manually
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# sslyze via pip
pip install sslyze

# sqlmap
sudo apt install sqlmap        # Debian/Ubuntu
brew install sqlmap            # macOS
```

**On Windows:**
```powershell
# Download pre-built binaries from each tool's GitHub releases page
# and place them in a directory that is in your PATH (e.g. C:\Tools\bin)

# Or install via Scoop (https://scoop.sh)
scoop install nmap curl

# sslyze and sqlmap via pip
pip install sslyze sqlmap
```

### Step 5 — Configure environment

```bash
# Copy the example file
cp .env.example .env   # Linux/macOS
copy .env.example .env  # Windows

# Open .env and add your Anthropic API key
```

Edit `.env`:
```env
PYTHONDONTWRITEBYTECODE=1
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx
```

Get your API key at [console.anthropic.com](https://console.anthropic.com/).

### Step 6 — Update Nuclei templates

```bash
nuclei -update-templates
```

---

## Configuration

All configuration is done through the `.env` file and CLI arguments.

### `.env` Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | For AI mode | Your Anthropic API key |
| `PYTHONDONTWRITEBYTECODE` | No | Prevents `.pyc` file generation |

### CLI Arguments

| Flag | Default | Description |
|---|---|---|
| `--target <domain>` | Interactive prompt | Target domain or IP — skips the interactive prompt |
| `--output <dir>` | `.` (current dir) | Directory where the HTML report is saved |
| `--no-ai` | Off | Disables all AI features — runs fully offline with fallback logic |

---

## Usage

### Basic scan (interactive)

```bash
python phantomai.py
```

You will be prompted to:
1. Select mode: `a` (Web) or `b` (Network)
2. Enter the target domain or IP

### Scan with target specified

```bash
python phantomai.py --target example.com
```

### Save report to a specific folder

```bash
python phantomai.py --target example.com --output ./reports
```

### Run without AI (no API key required)

```bash
python phantomai.py --target example.com --no-ai
```

### Full example with all flags

```bash
python phantomai.py --target testphp.vulnweb.com --output ./reports
```

### Using the backward-compatible entry point

```bash
python main.py --target example.com
```

---

## Scan Phases

PhantomAI runs a sequential 6-phase pipeline. Each phase feeds data into the next.

### Phase 0 — Target Validation & Fingerprinting
- Validates that the target is reachable (HTTP/HTTPS or ICMP/nmap)
- Probes HTTP headers and HTML to detect: framework, CMS, WAF, server, language
- AI (Haiku) enriches the fingerprint when a key is available
- **Output:** `stack` dict passed to all downstream phases

### Phase 1 — Reconnaissance
- Enumerates subdomains via `subfinder`, `assetfinder`, and `amass`
- Detects live hosts using `httpx`
- Gathers historical URLs from `gau` (Google, Archive.org, URLScan) and `waybackurls`
- AI (Haiku) scores and prioritizes the top 50 attack-surface URLs from potentially 1000+
- **Output:** `subdomains`, `live_hosts`, `urls`

### Phase 2 — Enumeration
- Fuzzes directories with `ffuf` using the bundled `wordlists/dirs.txt`
- AI (Haiku) appends stack-specific paths to the wordlist (e.g., `/artisan`, `/.env` for Laravel)
- Extracts all parameterized URLs using `urllib.parse` — proper query string parsing, not naive `?` splitting
- **Output:** `fuzz` hits, `params` (parameterized URLs), `param_names`

### Phase 3 — Vulnerability Analysis
- **A01/A03/A05/A06:** `nuclei` with medium/high/critical severity filter
- **A03 XSS:** `dalfox` on top 5 prioritized URLs
- **A03 SQLi:** `sqlmap` with level 2 / risk 2 on top 5 URLs
- **A02:** `sslyze` TLS/SSL configuration audit
- **A10 SSRF:** Custom probes against AWS/GCP metadata endpoints and localhost
- **A07:** `ffuf` against 35 common auth/session endpoints using temp wordlist
- AI (Haiku) triages all tool output — removes false positives, maps each finding to OWASP 2025, assigns severity and confidence
- **Output:** `triaged` list of structured findings

### Phase 4 — Exploitation
- AI (Sonnet) generates context-aware payloads per parameter name + detected stack
  - `id=` → SQLi payloads  |  `search=` → XSS  |  `url=` → SSRF  |  `file=` → LFI
  - Fallback payloads used when AI is unavailable
- **GET exploitation:** injects into query string parameters, compares against baseline response
- **POST exploitation:** discovers HTML form fields, resolves action URLs, tests via `requests.post`
- Detection uses **response diffing** (status code change + body length + known error patterns) — not simple string matching
- SSTI uses `{{523*523}}` → checks for `273529` (statistically safe, won't appear in normal pages)
- **Output:** confirmed hits with method, parameter, payload, and indicator list

### Phase 5 — Report Generation
- AI (Sonnet) synthesizes all findings into a structured JSON report:
  - Title, OWASP category, CWE ID, CVSS estimate, description, evidence, stack-specific remediation, OWASP reference URL
  - 3-sentence executive summary for non-technical stakeholders
- Falls back to rule-based report if AI unavailable
- HTML report rendered via Jinja2 and saved to disk
- Terminal summary printed with severity counts and top 3 critical findings

---

## Output & Reports

### Terminal Output

```
  ██████╗ ██╗  ██╗ ...
  AI-Powered Penetration Testing Framework  |  OWASP 2025  |  v1.0

[+] AI engine ready (Haiku + Sonnet)

[*] Phase 0: Target Validation & Fingerprinting
[+] Stack detected: framework=Laravel, server=nginx/1.24, waf=Cloudflare

[*] Phase 1: Reconnaissance
    Subdomains : 14 | Live hosts : 9 | URLs : 347

[*] Phase 2: Enumeration
    Fuzz hits : 23 | Params found : 41

[*] Phase 3: Vulnerability Analysis
    [*] Running nuclei...
    [*] Running dalfox on 5 URLs...
    [*] Running sqlmap on 5 URLs...
    [*] Running sslyze (TLS/SSL check)...
    [*] Probing for SSRF...
    [*] Fuzzing auth endpoints...
    Triaged findings : 7

[*] Phase 4: Exploitation
    [*] Discovering POST forms...
    [*] Testing 3 POST form(s)...
    Exploitation results : 2

[*] Phase 5: Report Generation

============================================================
  SCAN SUMMARY
============================================================
  Target      : example.com
  Overall Risk: HIGH
  Critical    : 0
  High        : 3
  Medium      : 4
  Low         : 1
============================================================

  TOP FINDINGS:
  1. [HIGH] SQL Injection via parameter 'id' (A03 — Injection)
  2. [HIGH] TLS 1.0 Enabled (A02 — Cryptographic Failures)
  3. [HIGH] Admin Panel Exposed at /admin (A05 — Security Misconfiguration)
============================================================

[+] HTML report saved: D:\reports\report_20250508_143022.html
```

### HTML Report

The HTML report (`report_YYYYMMDD_HHMMSS.html`) includes:

- **Risk matrix** — Critical / High / Medium / Low counts with colour-coded cards
- **Executive summary** — 3 sentences written by AI for non-technical readers
- **Target profile** — detected tech stack (framework, CMS, WAF, server, language)
- **Recon summary** — subdomain count, live hosts, URL count
- **Finding cards** (one per vulnerability):
  - Severity badge (colour-coded)
  - OWASP 2025 category badge
  - CWE ID
  - CVSS score estimate
  - Technical description
  - Evidence snippet (from scanner output)
  - Remediation guidance (stack-specific when AI is used)
  - OWASP reference link

---

## Cost Breakdown

| Phase | Model | Est. Tokens | Est. Cost |
|---|---|---|---|
| Phase 0 — Stack fingerprint | Haiku | ~200 | $0.00016 |
| Phase 1 — URL prioritization | Haiku | ~800 | $0.00064 |
| Phase 2 — Wordlist hints | Haiku | ~150 | $0.00012 |
| Phase 3 — False positive triage | Haiku | ~1500 | $0.00120 |
| Phase 4 — Payload generation | Sonnet | ~500 | $0.00150 |
| Phase 5 — Report generation | Sonnet | ~1500 | $0.00450 |
| **Total per scan** | | **~4650** | **~$0.008** |

Prompt caching reduces repeat-call costs by up to 90%.

---

## Legal Disclaimer

> **PhantomAI is designed exclusively for authorized security testing.**
>
> - Only use this tool against systems you own or have **explicit written permission** to test.
> - Unauthorized use against systems you do not own is **illegal** in most jurisdictions and may result in criminal prosecution.
> - The authors accept no liability for misuse or damage caused by this tool.
> - Always follow responsible disclosure practices when reporting vulnerabilities.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
