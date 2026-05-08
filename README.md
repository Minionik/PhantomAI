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

**PhantomAI** is an AI-powered, automated penetration testing framework that covers the full **OWASP Top 10 (2025)** attack surface. It supports three AI tiers — including a **completely free local mode** using Ollama — so you can run full AI-assisted scans with zero API cost.

> **For authorized security testing only.** Always obtain written permission before testing any target.

---

## Table of Contents

- [Features](#features)
- [OWASP 2025 Coverage](#owasp-2025-coverage)
- [AI Tiers](#ai-tiers)
- [AI Integration Details](#ai-integration-details)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scan Phases](#scan-phases)
- [Output & Reports](#output--reports)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

- **Full 6-phase pentest pipeline** — recon → enumeration → vuln analysis → exploitation → reporting
- **OWASP 2025 Top 10** coverage across all phases with per-finding categorization
- **AI-powered at every phase** — tech stack fingerprinting, URL prioritization, false positive triage, context-aware payload generation, executive reporting
- **Three AI tiers** — free (Ollama/local), basic (Claude Haiku), pro (Claude Haiku + Sonnet)
- **Zero-cost AI mode** — runs entirely on local Ollama models, no API key, no internet required
- **GET + POST exploitation** — discovers and tests HTML form fields automatically, not just query parameters
- **SSTI-safe detection** — uses unique computed markers (`{{523*523}}=273529`) instead of generic numbers that cause false positives
- **Response diffing** — compares baseline vs. payload response (status code + body length + content) for reliable detection
- **AI-generated HTML report** — dark-themed, professional output with OWASP badges, CWE IDs, CVSS scores, evidence blocks, and stack-specific remediation
- **Graceful `--no-ai` mode** — full scan with rule-based fallback when AI is unavailable

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

## AI Tiers

PhantomAI has three AI tiers. Set `AI_TIER` in your `.env` file — or let it auto-detect.

| Tier | `AI_TIER` value | Cost | Requirement | Quality |
|------|----------------|------|-------------|---------|
| **Free** | `free` | **$0.00** | Ollama installed locally | Good (depends on local model) |
| **Basic** | `basic` | ~$0.001/scan | Anthropic API key | Better (Claude Haiku) |
| **Pro** | `pro` | ~$0.008/scan | Anthropic API key | Best (Haiku + Sonnet) |

**Auto-detection** (`AI_TIER=auto`, the default):
- No `ANTHROPIC_API_KEY` set → **Free tier** (Ollama)
- `ANTHROPIC_API_KEY` is set → **Pro tier** (Haiku + Sonnet)

### Free Tier — Ollama (Zero Cost)

Runs a local AI model on your machine. No internet required after setup. No API key needed.

**How it works:** PhantomAI calls your local Ollama server (`http://localhost:11434`) using the standard Ollama chat API. The same prompts run — tech fingerprinting, URL scoring, payload generation, report writing — just through a local model instead of Claude.

**Recommended models:**

| Model | VRAM | Speed | Best For |
|---|---|---|---|
| `llama3.2` | ~2 GB | Fast | Default — good all-rounder |
| `llama3.1:8b` | ~5 GB | Medium | Better reasoning, better JSON |
| `mistral` | ~4 GB | Fast | Strong JSON output compliance |
| `qwen2.5:7b` | ~5 GB | Medium | Best for report generation |

**Setup:**
```bash
# 1. Install Ollama
# → https://ollama.com/download

# 2. Pull a model
ollama pull llama3.2

# 3. Set in .env
AI_TIER=free
OLLAMA_MODEL=llama3.2
```

### Basic Tier — Claude Haiku Only

Uses the Anthropic API but restricts **all** calls to Claude Haiku (the cheapest model). Even tasks that would normally use Sonnet (payload generation, report writing) are routed to Haiku. Lower quality than Pro but very cheap.

**Setup:**
```env
AI_TIER=basic
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx
```

### Pro Tier — Claude Haiku + Sonnet

Full capability. Cheap tasks (triage, classification, URL scoring) use **Haiku**. Complex tasks (payload generation, full OWASP report with CVSS + remediation) use **Sonnet**. Estimated cost ~$0.008 per scan.

**Setup:**
```env
AI_TIER=pro
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx
```

---

## AI Integration Details

### AI Touchpoints Per Scan

| Phase | AI Task | Free (Ollama) | Basic (Haiku) | Pro (Haiku+Sonnet) |
|---|---|---|---|---|
| Phase 0 | Identify framework, CMS, WAF from headers + HTML | Local model | Haiku | Haiku |
| Phase 1 | Score + prioritize top 50 attack-surface URLs | Local model | Haiku | Haiku |
| Phase 2 | Suggest stack-specific directory paths for ffuf | Local model | Haiku | Haiku |
| Phase 3 | Triage scanner output — remove false positives | Local model | Haiku | Haiku |
| Phase 4 | Generate context-aware payloads per param + stack | Local model | Haiku | **Sonnet** |
| Phase 5 | Write OWASP-mapped report with CVSS + remediation | Local model | Haiku | **Sonnet** |

### Cost Controls (Paid Tiers)

- **Prompt caching** (`cache_control: ephemeral`) on all system prompts — up to 90% cost reduction on repeat calls
- All tool output **truncated to 3000 chars** before any API call
- AI calls **skipped entirely** when a phase returns empty results
- `--no-ai` flag disables all AI calls

### Cost per Scan (Paid Tiers)

| Phase | Basic (Haiku all) | Pro (Haiku + Sonnet) |
|---|---|---|
| Phase 0 — Stack fingerprint | ~$0.00016 | ~$0.00016 |
| Phase 1 — URL prioritization | ~$0.00064 | ~$0.00064 |
| Phase 2 — Wordlist hints | ~$0.00012 | ~$0.00012 |
| Phase 3 — False positive triage | ~$0.00120 | ~$0.00120 |
| Phase 4 — Payload generation | ~$0.00025 | ~$0.00150 |
| Phase 5 — Report generation | ~$0.00075 | ~$0.00450 |
| **Total** | **~$0.003** | **~$0.008** |

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
│   ├── ai_engine.py                    # Tiered AI client (Ollama / Haiku / Sonnet)
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
- Python **3.10 or higher** (uses `type unions`, `list[str]` hints)

### External Tools
PhantomAI orchestrates these tools — they must be installed and available in your `PATH`:

| Tool | Purpose | Install |
|---|---|---|
| `subfinder` | Subdomain enumeration | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| `assetfinder` | Asset discovery | [tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) |
| `amass` | Subdomain enumeration | [owasp-amass/amass](https://github.com/owasp-amass/amass) |
| `httpx` | Live host detection | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| `gau` | URL gathering | [lc/gau](https://github.com/lc/gau) |
| `waybackurls` | Wayback Machine URLs | [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) |
| `ffuf` | Directory + auth fuzzing | [ffuf/ffuf](https://github.com/ffuf/ffuf) |
| `nuclei` | Template-based vuln scanner | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| `dalfox` | XSS scanner | [hahwul/dalfox](https://github.com/hahwul/dalfox) |
| `sqlmap` | SQL injection scanner | [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) |
| `sslyze` | TLS/SSL scanner | `pip install sslyze` |
| `curl` | HTTP requests (SSRF probes) | Pre-installed on most systems |
| `nmap` | Port scanning | [nmap.org](https://nmap.org/download.html) |

> **Tip:** Most Go-based tools can be bulk-installed with [pdtm](https://github.com/projectdiscovery/pdtm) — Project Discovery's tool manager.

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

Installs: `anthropic`, `jinja2`, `requests`, `python-dotenv`

### Step 4 — Install external tools

**Linux/macOS (using pdtm):**
```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install subfinder httpx nuclei dalfox ffuf gau
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install -v github.com/owasp-amass/amass/v4/...@master
pip install sslyze
sudo apt install sqlmap nmap   # Debian/Ubuntu
```

**Windows (Scoop + pip):**
```powershell
scoop install nmap curl
pip install sslyze sqlmap
# Download remaining Go binaries from their GitHub releases pages
```

### Step 5 — Configure your AI tier

```bash
cp .env.example .env   # Linux/macOS
copy .env.example .env  # Windows
```

Then edit `.env` for your chosen tier:

**Free tier (Ollama — zero cost):**
```env
AI_TIER=free
OLLAMA_MODEL=llama3.2
```
Also install Ollama and pull the model:
```bash
# Install from https://ollama.com
ollama pull llama3.2
ollama serve   # keep this running in a separate terminal
```

**Basic tier (Claude Haiku — cheapest paid):**
```env
AI_TIER=basic
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx
```

**Pro tier (Claude Haiku + Sonnet — best quality):**
```env
AI_TIER=pro
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx
```

Get your Anthropic key at [console.anthropic.com](https://console.anthropic.com/).

### Step 6 — Update Nuclei templates

```bash
nuclei -update-templates
```

---

## Configuration

### `.env` Variables

| Variable | Default | Description |
|---|---|---|
| `AI_TIER` | `auto` | AI tier: `free`, `basic`, `pro`, or `auto` |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL (free tier) |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model to use (free tier) |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (basic/pro tiers) |
| `PYTHONDONTWRITEBYTECODE` | `1` | Prevents `.pyc` file generation |

### CLI Arguments

| Flag | Default | Description |
|---|---|---|
| `--target <domain>` | Interactive prompt | Target domain or IP |
| `--output <dir>` | `.` (current dir) | Directory to save HTML report |
| `--no-ai` | Off | Disable all AI — rule-based fallback only |

---

## Usage

### Basic scan (interactive prompt)

```bash
python phantomai.py
```

### Scan with target specified

```bash
python phantomai.py --target example.com
```

### Save report to a specific folder

```bash
python phantomai.py --target example.com --output ./reports
```

### Run without any AI

```bash
python phantomai.py --target example.com --no-ai
```

### Override AI tier at runtime via .env

```bash
# Temporarily use free tier for this scan
AI_TIER=free python phantomai.py --target example.com
```

### Startup output examples by tier

**Free tier:**
```
[+] AI tier: FREE  (Ollama / llama3.2)
```

**Basic tier:**
```
[+] AI tier: BASIC (Claude Haiku only)
```

**Pro tier:**
```
[+] AI tier: PRO   (Claude Haiku + Sonnet)
```

---

## Scan Phases

PhantomAI runs a sequential 6-phase pipeline. Each phase feeds data into the next.

### Phase 0 — Target Validation & Fingerprinting
- Validates that the target is reachable (HTTP/HTTPS or ICMP/nmap)
- Probes HTTP headers and HTML to detect: framework, CMS, WAF, server, language
- AI enriches the fingerprint with the detected stack
- **Output:** `stack` dict passed to all downstream phases

### Phase 1 — Reconnaissance
- Enumerates subdomains via `subfinder`, `assetfinder`, and `amass`
- Detects live hosts using `httpx`
- Gathers historical URLs from `gau` and `waybackurls`
- AI scores and prioritizes the top 50 attack-surface URLs from potentially 1000+
- **Output:** `subdomains`, `live_hosts`, `urls`

### Phase 2 — Enumeration
- Fuzzes directories with `ffuf` using the bundled `wordlists/dirs.txt`
- AI appends stack-specific paths to the wordlist (e.g., `/artisan`, `/.env` for Laravel)
- Extracts all parameterized URLs using proper `urllib.parse` query string parsing
- **Output:** `fuzz` hits, `params` (parameterized URLs), `param_names`

### Phase 3 — Vulnerability Analysis
- **A01/A03/A05/A06:** `nuclei` with medium/high/critical severity filter
- **A03 XSS:** `dalfox` on top 5 prioritized URLs
- **A03 SQLi:** `sqlmap` on top 5 URLs
- **A02:** `sslyze` TLS/SSL configuration audit
- **A10 SSRF:** Custom probes against cloud metadata endpoints and localhost
- **A07:** `ffuf` against 35 common auth/session endpoints
- AI triages all tool output — removes false positives, maps to OWASP 2025, assigns severity
- **Output:** `triaged` list of structured findings

### Phase 4 — Exploitation
- AI generates context-aware payloads per parameter name + detected stack
- **GET exploitation:** injects into query string parameters with baseline comparison
- **POST exploitation:** discovers HTML form fields, tests via `requests.post`
- Detection uses response diffing — not simple string matching
- SSTI uses `{{523*523}}` → checks for `273529`
- **Output:** confirmed hits with method, parameter, payload, and indicator list

### Phase 5 — Report Generation
- AI synthesizes all findings into a structured report with OWASP category, CWE ID, CVSS estimate, evidence, stack-specific remediation
- Falls back to rule-based report if AI unavailable
- HTML report rendered via Jinja2 and saved to disk
- Terminal summary with severity counts and top 3 critical findings

---

## Output & Reports

### Terminal Summary

```
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

### HTML Report Contents

- Risk matrix — Critical / High / Medium / Low counts (colour-coded)
- Executive summary — written by AI for non-technical readers
- Target profile — detected tech stack
- Recon summary — subdomain count, live hosts, URL count
- Per-finding cards: severity badge, OWASP badge, CWE ID, CVSS, description, evidence, remediation, reference link

---

## Legal Disclaimer

> **PhantomAI is designed exclusively for authorized security testing.**
>
> - Only use this tool against systems you own or have **explicit written permission** to test.
> - Unauthorized use against systems you do not own is **illegal** in most jurisdictions.
> - The authors accept no liability for misuse or damage caused by this tool.
> - Always follow responsible disclosure practices when reporting vulnerabilities.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
