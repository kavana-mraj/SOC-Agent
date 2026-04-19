# SOC Agent

Automated Security Operations Center pipeline that ingests network traffic and logs, detects threats, triages incidents, and generates response recommendations — all without manual analyst intervention for high-confidence cases.

---

## What the pipeline does

```
PCAP / Log File
      │
      ▼
detection_engine   — rule-based threat detection (suspicious destinations, port scans, etc.)
      │
      ▼
triage_agent       — severity scoring, priority assignment, SLA tier
      │
      ▼
investigation_agent — enrichment: threat intel lookup, asset context, MITRE ATT&CK mapping
      │
      ▼
decision_agent     — confidence scoring; routes high-confidence cases to auto-close,
                     low-confidence cases to human review queue
      │
      ├─► [auto-close]       case saved, status = resolved
      │
      └─► [human review]     case queued for analyst approval/rejection + feedback
              │
              ▼
      response_agent  — recommended containment actions (block IP, isolate host, etc.)
              │
              ▼
      case_manager    — serialize full case to cases/<name>_<timestamp>.json
```

### Detection rules (current)
| Rule | Trigger |
|------|---------|
| `repeated_suspicious_destination` | ≥3 connections to `8.8.8.8` |
| `suspicious_port_access` | any TCP connection to port 22 |

---

## UI features

Start the API server:

```bash
uvicorn api:app --reload --port 8000
```

Open `http://localhost:8000` in browser.

### Upload PCAP from UI

1. Click **Ingest Logs** in nav
2. Drag-and-drop or select `.pcap` / `.pcapng` file (max 50 MB)
3. Click **Upload & Analyze** — pipeline runs immediately, case created on completion

Supported formats: `.pcap` `.pcapng` `.csv` `.log` `.txt` `.json`

Pre-configured source type parsers: Splunk `stream:tcp` CSV, AWS VPC Flow Logs, GCP VPC Flow Logs (JSON lines), iptables/firewall logs.

### Live pipeline logs

**Cases → Run Pipeline** button triggers `python main.py` as subprocess.  
Output streams line-by-line to browser via `StreamingResponse` — no page refresh needed.

---

## Architecture

| Module | Role |
|--------|------|
| `main.py` | CLI entrypoint — iterates `PCAP_OPTIONS` in `config.py` |
| `soc_runner.py` | Orchestrates full agent chain for one PCAP |
| `api.py` | FastAPI backend — REST + streaming endpoints |
| `frontend/index.html` | Single-page dashboard (cases, review queue, ingest, run) |
| `detection_engine.py` | Rule-based packet analysis |
| `triage_agent.py` | Severity + SLA classification |
| `investigation_agent.py` | Threat intel + asset enrichment |
| `decision_agent.py` | Confidence routing (auto vs. human) |
| `response_agent.py` | Containment action recommendations |
| `case_manager.py` | Case persistence + SLA tracking |
| `human_review.py` | Review queue CRUD |
| `feedback_loop.py` | Analyst feedback aggregation + rule stats |
| `threat_intel.py` | IP/domain reputation lookup |
| `asset_context.py` | Host/asset metadata enrichment |
| `mitre_mapping.py` | MITRE ATT&CK tactic/technique tagging |
| `log_ingestor.py` | Multi-format log parser |
| `llm_connector.py` | OpenAI / NVIDIA LLM wrapper (`investigation_agent` calls it; NVIDIA streams at import time) |

---

## Threat Intelligence

`threat_intel.py` enriches every incident's source and destination IPs against two external APIs:

| API | Env var | Data returned |
|-----|---------|---------------|
| **AbuseIPDB** | `ABUSEIPDB_API_KEY` | Abuse confidence score (0–100), report count, country, ISP |
| **AlienVault OTX** | `OTX_API_KEY` | Pulse count, malicious flag, threat tags |

Combined threat score: `abuse_score × 0.7 + otx_score × 0.3`  
Verdict: `≥70` → malicious · `≥30` → suspicious · else clean  
Private IPs are skipped automatically. Missing keys degrade gracefully (score = 0).

---

## Setup

```bash
cp .env.example .env
# fill in keys — all optional, pipeline degrades gracefully without them

uv sync          # or: pip install -r requirements.txt
```

### Environment variables

| Variable | Module | Purpose |
|----------|--------|---------|
| `OPENAI_API_KEY` | `llm_connector.py` | GPT-4.1-mini for investigation |
| `NVIDIA_API_KEY` | `llm_connector.py` | NVIDIA NIM streaming (called at import time) |
| `ABUSEIPDB_API_KEY` | `threat_intel.py` | IP abuse reputation |
| `OTX_API_KEY` | `threat_intel.py` | AlienVault OTX threat intel |

### Run CLI pipeline

```bash
python main.py
```

### Run API + UI

```bash
uvicorn api:app --reload --port 8000
# open http://localhost:8000
```

---

## Planned

- LLM-backed agent reasoning (keys wired, agents not yet calling LLM)
- SIEM / EDR / firewall vendor integrations
- Confidence score tuning via analyst feedback loop
- Auth + multi-tenant support
