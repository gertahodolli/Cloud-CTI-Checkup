# CTI-Checkup

**CLI and optional web UI for cloud security posture checks and threat intelligence.** Run AWS security scans, look up IPs and domains, analyze CloudTrail events, and extract IOCs—all from your machine with no cloud backend.

---

## What it does

- **AWS security scans** — S3, IAM, and EC2 checks with configurable rules and risk scoring (0–100).
- **Threat intelligence** — IP reputation (AbuseIPDB) and domain lookups (IPInfo), with optional cloud attribution.
- **CloudTrail analysis** — Correlate events with intel; summarize with AI or deterministic (baseline) mode; **extract IOCs** (IPs, identities, access keys) via regex.
- **IAM identity risk** — Identity-level risk profiles from IAM and scan data.
- **Compliance view** — Map findings to CIS AWS, NIST CSF, ISO 27001, SOC 2 (driven by scan results).
- **Optional web UI** — View runs, start scans, run CloudTrail analysis, view IOCs, do threat intel lookups, and manage config and API keys locally.

Everything runs **on your machine**. No sign-in; the UI only reads/writes local files and runs the CLI.

---

## Recent updates

- **Cloud Posture Score** — Score is now 0–100 (higher = better). Displayed consistently on Dashboard, run list, and Reports.
- **CloudTrail run naming** — Runs auto-named as `CloudTrail_Baseline 2/15/2026 03:58 PM` or `CloudTrail_AiInsights 2/15/2026 03:58 PM`.
- **CloudTrail redirects** — Baseline analysis redirects to **IOCs**; AI analysis redirects to **AI Insights**.
- **Run management** — **New scan** button and **delete scan** (trash icon) in the run dropdown.
- **CloudTrail scan display** — CloudTrail runs show type (CloudTrail_Baseline / CloudTrail_AiInsights) instead of findings/score.
- **AI Insights** — Baseline runs show a clear message; Event Timeline dates fixed when backend uses `time` field.
- **CloudTrail upload persistence** — Uploaded file and mode persist when navigating between tabs.
- **AI config** — CloudTrail AI mode prefers `config/ai.local.yaml` when no explicit config is set.

---

## What it supports

| Area | Supported |
|------|-----------|
| **Cloud** | AWS (S3, IAM, EC2) |
| **Threat intel** | AbuseIPDB (IP), IPInfo (domain); optional VirusTotal |
| **AI / summarization** | OpenAI (CloudTrail); baseline mode works without AI |
| **Config** | YAML (e.g. `config/local.yaml`); API keys via env or UI Settings |
| **Output** | Human (table/text) and JSON; runs stored under `~/.cti-checkup/runs` (or configurable path) |
| **Platforms** | Windows, macOS, Linux; CLI in PATH where the API server runs |

---

## Quick start

### CLI only

```bash
# Install CLI
pip install -e .
cti-checkup --help

# Run an AWS scan
cti-checkup cloud aws scan --output json

# Look up an IP (needs AbuseIPDB key in env)
cti-checkup intel ip 8.8.8.8 --output json

# Analyze CloudTrail events (no AI required)
cti-checkup ai summarize cloudtrail --events ./cloudtrail_events.json --mode baseline
```

### Web UI

1. **Install CLI** (above) and add API keys to the **project root `.env`** or `~/.cti-checkup/.env` (see [Environment variables](#environment-variables)).
2. **Start the API server** (from the same environment where `cti-checkup` is in PATH):
   ```bash
   cd frontend/server && npm install && npm start
   ```
3. **Start the frontend:**
   ```bash
   cd frontend && npm install && npm run dev
   ```
4. Open **http://localhost:5173** — use Dashboard, Findings, Threat Intel, CloudTrail, IOCs, Settings, etc.

---

## Requirements

- **Python 3.10+** — for the CLI.
- **Node.js 16+** — only if you use the web UI.
- **AWS credentials** — for cloud commands (e.g. `~/.aws/credentials` or `aws configure`).
- **Threat intel** — AbuseIPDB, IPInfo, and VirusTotal API keys (see [Environment variables](#environment-variables)).
- **UI + CLI** — When using the UI, `cti-checkup` must be installed and in the **PATH** of the process that runs the API server (e.g. same terminal or same env).

---

## Installation

### 1. CLI (required for scans and intel)

```bash
pip install -r requirements.txt
# or
pip install -e .
```

Verify:

```bash
cti-checkup --help
```

### 2. Web UI (optional)

```bash
cd frontend
npm install
cd server
npm install
```

---

## How to start the tool

### Start the CLI

Use any command from the [Commands (CLI)](#commands-cli) section. Examples:

```bash
# Full AWS scan, output to terminal
cti-checkup cloud aws scan --output json

# Write scan to a file
cti-checkup cloud aws scan --output json --out ./my-run/scan_result.json

# Threat intel (requires API keys in env)
cti-checkup intel ip 8.8.8.8 --output json
cti-checkup intel domain example.com --output json
cti-checkup intel hash <md5|sha1|sha256> --output json   # VirusTotal

# CloudTrail: analyze events and extract IOCs (baseline = no AI)
cti-checkup ai summarize cloudtrail --events ./events.json --mode baseline --output json --out ./summary.json
```

### Start the web UI

1. **Start the API server** (from a shell where `cti-checkup` is in PATH):
   ```bash
   cd frontend/server
   npm start
   ```
   Default: http://localhost:3001. The server loads the **project root `.env`** first, then `~/.cti-checkup/.env`, so spawned CLI processes get your API keys.

2. **Start the frontend:**
   ```bash
   cd frontend
   npm run dev
   ```
   Open the URL Vite prints (usually http://localhost:5173).

3. **Use the UI:**
   - **Dashboard** — Select a run; view posture score (0–100), findings, compliance.
   - **Findings / Assets / Compliance / Alerts / Reports** — Driven by the selected run.
   - **AI Insights** — View CloudTrail AI summary for a run (AI mode only; baseline runs show a prompt to re-run with AI).
   - **CloudTrail** — Upload a CloudTrail events file, choose Baseline or AI, run analysis. Upload persists when switching tabs. Baseline redirects to IOCs; AI redirects to AI Insights.
   - **Threat Intel** — IP, domain, and file hash lookups; batch IP lookup (e.g. paste IOCs from CloudTrail).
   - **IOCs** — View extracted indicators (IPs, identities, access keys) for a run with CloudTrail analysis.
   - **Run dropdown** — New scan, select run, rename (pencil), delete (trash). CloudTrail runs show type (CloudTrail_Baseline / CloudTrail_AiInsights).
   - **Start Scan** — Runs `cti-checkup cloud aws scan`; optional profile/regions in the modal.
   - **Settings** — YAML config path, runs directory, AWS profile, and API keys (saved to the **project root `.env`**).

If you see “Permission denied” or “CLI exited with code 1”, ensure `cti-checkup` is in PATH for the server process and that required API keys are in the project `.env`, `~/.cti-checkup/.env`, or exported in the shell.

---

## How to use (overview)

- **AWS security:** Run `cti-checkup cloud aws scan` (or from UI “Start Scan”). Results appear in the runs directory; select a run in the UI to see Findings, Assets, Compliance, Alerts, Reports.
- **Threat intel:** Use **Threat Intel** in the UI (or `cti-checkup intel ip` / `intel domain` / `intel hash`). Paste IPs from the IOCs page for batch lookup. Hash lookup is powered by VirusTotal.
- **CloudTrail:** In the UI go to **CloudTrail**, upload a JSON/JSONL events file, choose Baseline (no AI) or AI, and run analysis. Baseline redirects to **IOCs**; AI redirects to **AI Insights**. Runs are auto-named (e.g. `CloudTrail_Baseline 2/15/2026 03:58 PM`).
- **Compliance:** Run an AWS scan first; the **Compliance** page shows framework coverage based on findings (no data → “No Compliance Data”).
- **Config and secrets:** Use **Settings** in the UI (YAML path, runs directory, AWS profile, API keys) or set env vars / `--config` for the CLI.

---

## Environment variables

Secrets are read from (in order): **project root `.env`**, then `~/.cti-checkup/.env`, then the process environment. Keys you save in the UI are written to the **project root `.env`**.

### Quick setup

1. Copy the template and add your keys to the **project root** (or to `~/.cti-checkup/.env` as a fallback):
   ```bash
   cp .env.example .env
   # Edit .env and set at least:
   #   CTICHECKUP_ABUSEIPDB_API_KEY=...   (for intel ip)
   #   CTICHECKUP_IPINFO_TOKEN=...        (for intel domain)
   ```
2. **Do not commit `.env`** — it is in `.gitignore`. Use `.env.example` as the template.
3. Start the API server from the **same environment** where `cti-checkup` is installed so the CLI gets those keys when the UI starts a scan or intel lookup.

### Reference

See **`.env.example`** in the project root. Summary:

| Variable | Purpose |
|----------|---------|
| `VITE_API_URL` | Frontend API base (e.g. `http://localhost:3001/api`). Use `frontend/.env` if you change it. |
| `PORT` | API server port (default 3001). |
| `CTICHECKUP_ABUSEIPDB_API_KEY` | **Required** for `intel ip`. [AbuseIPDB](https://www.abuseipdb.com/). |
| `CTICHECKUP_IPINFO_TOKEN` | **Required** for `intel domain`. [IPInfo](https://ipinfo.io/). |
| `CTICHECKUP_IPINFO_REFERRER` | Optional; set if your IPinfo token has “Limit Referring Domains” enabled. |
| `CTICHECKUP_AI_OPENAI_API_KEY` | For AI summarization (e.g. CloudTrail). |
| `CTICHECKUP_VIRUSTOTAL_API_KEY` | Optional; for `intel hash`. [VirusTotal](https://www.virustotal.com/). |
| `CTICHECKUP_CONFIG` | Optional path to YAML config. |
| `AWS_PROFILE`, `AWS_REGIONS` | Optional; UI can also set profile/regions in Settings. |
| `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` | Optional; use if AWS config is not in `~/.aws`. |

**Where to put them**

- **Project (recommended):** Use the **project root `.env`**. The UI saves API keys here. Do not commit it.
- **User directory (fallback):** Use `~/.cti-checkup/.env` if you prefer keys outside the repo.
- **Frontend:** Copy `VITE_API_URL` (and any other `VITE_*`) into `frontend/.env` if needed.

---

## Configuration

### YAML config

Use a YAML file (e.g. `config/local.yaml`) with optional env expansion. Set `--config /path/to/config.yaml` or `CTICHECKUP_CONFIG`.

- **AWS:** `aws.regions`, `aws.enabled_services`
- **Checks:** `checks.s3`, `checks.iam`, `checks.ec2` (thresholds, which checks to run)
- **Intel:** `intel.timeout_seconds`, `intel.retry.max_attempts`, `intel.retry.backoff_seconds`
- **AI / indicators:** `ai.enabled`, `ai.indicators` (skip lists, display limits for IOCs). For CloudTrail AI mode, `config/ai.local.yaml` is used when no explicit config is set.
- **Cloud attribution:** `intel.cloud_attribution.enabled`, `intel.cloud_attribution.providers`
- **Risk scoring:** `risk_scoring.cap`, `risk_scoring.weights`

See `config/example.yaml` for a full template.

### Secrets

API keys are **not** stored in YAML. Use environment variables or UI **Settings → API keys**. The UI writes keys to the **project root `.env`** when you save (do not commit this file).

---

## Commands (CLI)

| Command | Description |
|---------|-------------|
| **Cloud / AWS** | |
| `cti-checkup cloud aws scan` | Full AWS scan (services enabled in config) |
| `cti-checkup cloud aws s3` | S3 checks only |
| `cti-checkup cloud aws iam` | IAM checks only |
| `cti-checkup cloud aws iam identities` | IAM identity risk profiles |
| `cti-checkup cloud aws ec2` | EC2 checks only |
| **Threat intel** | |
| `cti-checkup intel ip <ip>` | IP reputation (AbuseIPDB); optional cloud attribution |
| `cti-checkup intel domain <domain>` | Domain lookup (IPInfo); optional cloud attribution |
| `cti-checkup intel correlate cloudtrail --events <file>` | Correlate CloudTrail events with intel |
| **AI / CloudTrail** | |
| `cti-checkup ai summarize cloudtrail --events <file>` | Analyze CloudTrail events; extract IOCs; optional AI summary |
| | `--mode baseline` (default: no AI) or `--mode llm`; `--output human|json`; `-o` write to file |
| **Export** | |
| `cti-checkup export detections` | Export detection rules (from config) |
| **Eval** | |
| `cti-checkup eval run --scenario <name> --out <dir>` | Run evaluation scenario |
| `cti-checkup eval score --input <summary> --evidence <bundle>` | Score AI summary against evidence |

**Common options:** `--config`, `--profile`, `--regions`, `--output` (human|json), `--format` (table|text), `--out` / `-o` (write output to file).

---

## Output

- **Human:** Table or text summary; CloudTrail and IAM identities use their own formats.
- **JSON:** AWS/intel scans use a `ScanResult`-style structure (provider, regions, findings, summary, risk_score, etc.). CloudTrail summary and IOCs are in the AI summary JSON. The UI displays a **posture score** (100 − risk_score) so higher values indicate better security posture.

**Exit codes:** `0` success, `1` error, `2` partial success, `3` findings (with `--exit-on-findings`).

---

## Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for the full text.
