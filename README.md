# CTI-Checkup

Cloud security posture assessment and threat intelligence toolkit. Run AWS security scans, look up IPs and domains, analyze CloudTrail events, and extract IOCs, all from your machine with no cloud backend required.

**Author:** [Gerta Hodolli](https://www.linkedin.com/in/gertahodolli/)

## Features

- **AWS Security Scans** - S3, IAM, and EC2 checks with configurable rules and risk scoring (0-100)
- **Threat Intelligence** - IP reputation (AbuseIPDB), domain lookups (IPInfo), file hash lookups (VirusTotal)
- **CloudTrail Analysis** - Correlate events with threat intel, summarize with AI or deterministic baseline mode, extract IOCs (IPs, identities, access keys)
- **IAM Identity Risk** - Identity-level risk profiles built from IAM and scan data
- **Compliance Mapping** - Map findings to CIS AWS, NIST CSF, ISO 27001, SOC 2
- **Web UI (optional)** - Dashboard for viewing runs, starting scans, running CloudTrail analysis, threat intel lookups, and managing config

Everything runs locally. No sign-in, no cloud backend. The UI reads and writes local files and calls the CLI.

## Requirements

| Requirement | Details |
|-------------|---------|
| Python 3.10+ | CLI |
| Node.js 16+ | Web UI only |
| AWS credentials | For cloud commands (`~/.aws/credentials` or `aws configure`) |
| API keys | AbuseIPDB, IPInfo, VirusTotal (see [Environment Variables](#environment-variables)) |

## Quick Start

### CLI only

```bash
# Install CLI
pip install -r requirements.txt
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

1. Install the CLI dependencies and the CLI itself:

```bash
pip install -r requirements.txt
pip install -e .
```

2. Create a `.env` file and add your API keys:

```bash
cp .env.example .env
```

Edit `.env` with your keys (see [Environment Variables](#environment-variables) for the full list).

3. Start the API server in one terminal (from the same environment where `cti-checkup` is in PATH):

```bash
cd frontend/server && npm install && npm start
```

4. Start the frontend in a second terminal:

```bash
cd frontend && npm install && npm run dev
```

5. Open http://localhost:5173.

The `cti-checkup` CLI must be installed and available in the PATH of the process running the API server. If you see "Permission denied" or "CLI exited with code 1", check that the CLI is accessible and your API keys are configured.

## UI Pages

| Page | Description |
|------|-------------|
| Dashboard | Posture score (0-100), findings summary, compliance overview |
| Findings / Assets | Detailed scan results for the selected run |
| Compliance | Framework coverage based on scan findings |
| CloudTrail | Upload events, choose Baseline or AI mode, run analysis |
| AI Insights | AI-generated summary for CloudTrail runs (AI mode only) |
| IOCs | Extracted indicators (IPs, identities, access keys) from CloudTrail analysis |
| Threat Intel | IP, domain, and hash lookups; batch IP lookup from IOCs |
| Reports | Exportable summaries per run |
| Settings | YAML config, runs directory, AWS profile, API keys |

## Environment Variables

Secrets are read in this order: project root `.env`, then `~/.cti-checkup/.env`, then the process environment. The UI writes keys to the project root `.env`.

### Setup

```bash
cp .env.example .env
```

Edit `.env` and fill in your keys. Do not commit this file (it is in `.gitignore`).

### Reference

| Variable | Purpose |
|----------|---------|
| `CTICHECKUP_ABUSEIPDB_API_KEY` | Required for `intel ip`. [AbuseIPDB](https://www.abuseipdb.com/) |
| `CTICHECKUP_IPINFO_TOKEN` | Required for `intel domain`. [IPInfo](https://ipinfo.io/) |
| `CTICHECKUP_VIRUSTOTAL_API_KEY` | Optional. For `intel hash`. [VirusTotal](https://www.virustotal.com/) |
| `CTICHECKUP_AI_OPENAI_API_KEY` | Optional. For AI-powered CloudTrail summarization |
| `CTICHECKUP_IPINFO_REFERRER` | Optional. Set if your IPInfo token has domain restrictions |
| `VITE_API_URL` | Frontend API base URL (default: `http://localhost:3001/api`) |
| `PORT` | API server port (default: 3001) |
| `AWS_PROFILE` | AWS profile name (also configurable in UI Settings) |
| `AWS_REGIONS` | Comma-separated AWS regions |
| `CTICHECKUP_CONFIG` | Path to YAML config file |

## Configuration

Use a YAML config file (e.g. `config/local.yaml`) to customize scan behavior. Set with `--config /path/to/config.yaml` or `CTICHECKUP_CONFIG`.

Configurable areas:

- **AWS** - regions, enabled services
- **Checks** - S3, IAM, EC2 check thresholds and toggles
- **Intel** - timeouts, retry settings
- **AI / Indicators** - enable/disable AI, IOC skip lists, display limits
- **Cloud Attribution** - enable provider attribution for threat intel results
- **Risk Scoring** - score cap, category weights

See `config/example.yaml` for a full template.

API keys are never stored in YAML. Use environment variables or the UI Settings page.

## CLI Reference

| Command | Description |
|---------|-------------|
| `cti-checkup cloud aws scan` | Full AWS scan (S3, IAM, EC2) |
| `cti-checkup cloud aws s3` | S3 checks only |
| `cti-checkup cloud aws iam` | IAM checks only |
| `cti-checkup cloud aws iam identities` | IAM identity risk profiles |
| `cti-checkup cloud aws ec2` | EC2 checks only |
| `cti-checkup intel ip <ip>` | IP reputation lookup |
| `cti-checkup intel domain <domain>` | Domain lookup |
| `cti-checkup intel hash <hash>` | File hash lookup (VirusTotal) |
| `cti-checkup intel correlate cloudtrail --events <file>` | Correlate CloudTrail events with intel |
| `cti-checkup ai summarize cloudtrail --events <file>` | Analyze CloudTrail events and extract IOCs |
| `cti-checkup export detections` | Export detection rules |

Common flags: `--config`, `--profile`, `--regions`, `--output` (human/json), `--format` (table/text), `--out` / `-o` (write to file).

## Output

- **Human** - Table or text summary printed to the terminal
- **JSON** - Structured output with provider, regions, findings, summary, and risk score

The UI displays a posture score calculated as `100 - risk_score`, so higher values mean better security posture.

Exit codes: `0` success, `1` error, `2` partial success, `3` findings detected (with `--exit-on-findings`).

## Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```
## Results

Below are sample outputs from the Web UI after running an AWS security scan, CloudTrail analysis, and threat intelligence lookups.

**Security Dashboard**

<img width="1919" height="1079" alt="Image" src="https://github.com/user-attachments/assets/df234090-f474-4c60-a154-6779baed587f" />

**Findings**

<img width="1031" height="404" alt="Image" src="https://github.com/user-attachments/assets/ce2e9cda-2acd-4200-83f9-298ed4a0c43e" />

**CloudTrail Analysis**

<img width="1041" height="691" alt="Image" src="https://github.com/user-attachments/assets/2c83625d-8ab2-4c3b-b0b5-c3e5b65a75cf" />

**Threat Intelligence**

<img width="1024" height="580" alt="Image" src="https://github.com/user-attachments/assets/28ac793a-41cf-4589-b677-39f5b6efb244" />

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
