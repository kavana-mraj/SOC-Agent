"""FastAPI backend — serves cases, review queue, and pipeline trigger."""

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
import json
import os
import asyncio
import tempfile
import sys

import case_manager

_HERE = os.path.dirname(os.path.abspath(__file__))
import human_review
import feedback_loop
import log_ingestor
from detection_engine import detect_incident
from triage_agent import triage_incident
from investigation_agent import investigate_incident
from decision_agent import decide
from response_agent import respond_to_incident
from human_review import queue_for_review
from threat_intel import enrich_incident
from asset_context import enrich_incident_assets

app = FastAPI(title="SOC Agent API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")

@app.get("/")
def root():
    """Serve the index.html at root."""
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    raise HTTPException(404, "Frontend not found")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# ── Cases ──────────────────────────────────────────────────────────────────

@app.get("/api/cases")
def list_cases(status: Optional[str] = None, tier: Optional[str] = None):
    return case_manager.list_cases(status_filter=status, tier_filter=tier)


@app.get("/api/cases/summary/stats")
def case_stats():
    cases = case_manager.list_cases()
    severity_counts = {}
    tier_counts = {}
    status_counts = {}
    for c in cases:
        sev = c.get("incident", {}).get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        tier = c.get("analyst_tier", "unknown")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        st = c.get("status", "unknown")
        status_counts[st] = status_counts.get(st, 0) + 1
    return {
        "total": len(cases),
        "severity_counts": severity_counts,
        "tier_counts": tier_counts,
        "status_counts": status_counts
    }


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    path = os.path.join(_HERE, "cases", f"{case_id}.json")
    if not os.path.exists(path):
        raise HTTPException(404, f"Case {case_id} not found")
    with open(path) as f:
        case = json.load(f)
    case.setdefault("case_id", case_id)
    case.setdefault("status", "open")
    case.setdefault("analyst_tier", "L1")
    case["sla_status"] = case_manager.get_sla_status(case)
    return case


class StatusUpdate(BaseModel):
    status: str
    actor: Optional[str] = "analyst"


@app.patch("/api/cases/{case_id}/status")
def update_case_status(case_id: str, body: StatusUpdate):
    path = os.path.join(_HERE, "cases", f"{case_id}.json")
    if not os.path.exists(path):
        raise HTTPException(404, f"Case {case_id} not found")
    return case_manager.update_status(path, body.status, body.actor)


class NoteBody(BaseModel):
    note: str
    analyst: Optional[str] = "analyst"


@app.post("/api/cases/{case_id}/notes")
def add_note(case_id: str, body: NoteBody):
    path = os.path.join(_HERE, "cases", f"{case_id}.json")
    if not os.path.exists(path):
        raise HTTPException(404, f"Case {case_id} not found")
    return case_manager.add_note(path, body.note, body.analyst)


class EvidenceBody(BaseModel):
    description: str
    data: dict
    analyst: Optional[str] = "analyst"


@app.post("/api/cases/{case_id}/evidence")
def attach_evidence(case_id: str, body: EvidenceBody):
    path = os.path.join(_HERE, "cases", f"{case_id}.json")
    if not os.path.exists(path):
        raise HTTPException(404, f"Case {case_id} not found")
    return case_manager.attach_evidence(path, body.description, body.data, body.analyst)


class EscalateBody(BaseModel):
    from_tier: str
    reason: str
    actor: Optional[str] = "analyst"


@app.post("/api/cases/{case_id}/escalate")
def escalate_case(case_id: str, body: EscalateBody):
    path = os.path.join(_HERE, "cases", f"{case_id}.json")
    if not os.path.exists(path):
        raise HTTPException(404, f"Case {case_id} not found")
    try:
        return case_manager.escalate_case(path, body.from_tier, body.reason, body.actor)
    except ValueError as e:
        raise HTTPException(400, str(e))


# ── Review Queue ───────────────────────────────────────────────────────────

@app.get("/api/review-queue")
def get_review_queue(tier: Optional[str] = None):
    if tier:
        return human_review.list_by_tier(tier)
    return human_review.list_pending()


@app.get("/api/review-queue/{case_id}")
def get_review_entry(case_id: str):
    entry = human_review.get_entry(case_id)
    if not entry:
        raise HTTPException(404, f"Review entry {case_id} not found")
    return entry


class ReviewBody(BaseModel):
    analyst_notes: Optional[str] = ""
    analyst: Optional[str] = "analyst"


@app.post("/api/review-queue/{case_id}/approve")
def approve_case(case_id: str, body: ReviewBody):
    result = human_review.approve(case_id, body.analyst_notes, body.analyst)
    if not result:
        raise HTTPException(404, f"Case {case_id} not in queue")
    return result


@app.post("/api/review-queue/{case_id}/reject")
def reject_case(case_id: str, body: ReviewBody):
    result = human_review.reject(case_id, body.analyst_notes, body.analyst)
    if not result:
        raise HTTPException(404, f"Case {case_id} not in queue")
    return result


class EvidenceQueueBody(BaseModel):
    description: str
    data: dict
    analyst: Optional[str] = "analyst"


@app.post("/api/review-queue/{case_id}/evidence")
def add_evidence_to_queue(case_id: str, body: EvidenceQueueBody):
    result = human_review.add_evidence(case_id, body.description, body.data, body.analyst)
    if not result:
        raise HTTPException(404, f"Case {case_id} not in queue")
    return result


class QueueEscalateBody(BaseModel):
    from_tier: str
    reason: str
    actor: Optional[str] = "analyst"


@app.post("/api/review-queue/{case_id}/escalate")
def escalate_queue_entry(case_id: str, body: QueueEscalateBody):
    try:
        result = human_review.escalate(case_id, body.from_tier, body.reason, body.actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not result:
        raise HTTPException(404, f"Case {case_id} not in queue")
    return result


# ── Log / File Ingest ─────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {".csv", ".log", ".txt", ".json", ".pcap", ".pcapng"}
MAX_UPLOAD_MB = 50


def _run_pipeline_on_events(events: list, source_name: str) -> dict:
    """Run full SOC pipeline on pre-parsed events. Returns case dict."""
    incident = detect_incident(events)
    if not incident:
        return {"status": "no_incident", "events_parsed": len(events), "source_name": source_name}

    threat_intel = enrich_incident(incident)
    incident["threat_intel_verdict"] = threat_intel.get("overall_verdict", "unknown")
    incident["max_threat_score"] = threat_intel.get("max_threat_score", 0.0)

    asset_ctx = enrich_incident_assets(incident)
    incident["max_asset_criticality"] = asset_ctx.get("max_asset_criticality", "unknown")

    verdict = triage_incident(incident)
    investigation = investigate_incident(incident, events)
    decision = decide(incident, verdict, investigation)
    response = respond_to_incident(incident, verdict, decision)

    saved_file = case_manager.save_case(
        incident, verdict, investigation, response, source_name, decision,
        threat_intel=threat_intel, asset_context=asset_ctx
    )

    case_id = os.path.basename(saved_file).replace(".json", "")

    if decision["requires_human_review"]:
        queue_for_review(case_id, incident, verdict, investigation, decision)

    with open(saved_file) as f:
        case_data = json.load(f)
    case_data["sla_status"] = case_manager.get_sla_status(case_data)
    return {"status": "case_created", "case_id": case_id, "case": case_data}


@app.post("/api/ingest/upload")
async def ingest_upload(
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
    source_name: str = Form("")
):
    """Upload a log/CSV/PCAP file, run SOC pipeline, return case result."""
    fname = file.filename or "upload"
    ext = os.path.splitext(fname)[1].lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type {ext} not allowed. Use: {ALLOWED_EXTENSIONS}")

    content = await file.read()
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {MAX_UPLOAD_MB}MB limit")

    sname = source_name.strip() or os.path.splitext(fname)[0]

    # PCAP: write to temp file, use scapy
    if ext in (".pcap", ".pcapng"):
        from scapy.all import rdpcap
        from detection_engine import generate_events
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            packets = rdpcap(tmp_path)
            events = generate_events(packets)
        finally:
            os.unlink(tmp_path)
        detected_type = "pcap"
    else:
        # Text-based logs / CSV
        try:
            raw = content.decode("utf-8", errors="replace")
        except Exception as e:
            raise HTTPException(400, f"Cannot decode file: {e}")

        if source_type == "auto":
            detected_type, events = log_ingestor.auto_detect_and_parse(raw, fname)
        else:
            events = log_ingestor.ingest(source_type, raw)
            detected_type = source_type

    if not events:
        return {
            "status": "no_events",
            "message": "File parsed but no network events extracted. Check format or source_type.",
            "detected_type": detected_type,
            "filename": fname
        }

    result = _run_pipeline_on_events(events, sname)
    result["detected_type"] = detected_type
    result["events_parsed"] = len(events)
    result["filename"] = fname
    return result


@app.post("/api/ingest/upload-stream")
async def ingest_upload_stream(
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
    source_name: str = Form("")
):
    """Upload file and stream pipeline log lines, ending with a JSON result line."""
    fname = file.filename or "upload"
    ext = os.path.splitext(fname)[1].lower()

    content = await file.read()

    async def generate():
        if ext and ext not in ALLOWED_EXTENSIONS:
            yield f"[ERROR] File type {ext} not allowed. Accepted: {ALLOWED_EXTENSIONS}\n"
            yield "__RESULT__" + json.dumps({"status": "error", "message": f"File type {ext} not allowed"}) + "\n"
            return

        if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
            yield f"[ERROR] File exceeds {MAX_UPLOAD_MB}MB limit\n"
            yield "__RESULT__" + json.dumps({"status": "error", "message": "File too large"}) + "\n"
            return

        sname = source_name.strip() or os.path.splitext(fname)[0]
        yield f"[INFO] File received: {fname} ({len(content)//1024} KB)\n"

        try:
            if ext in (".pcap", ".pcapng"):
                from scapy.all import rdpcap
                from detection_engine import generate_events
                yield "[INFO] Parsing PCAP packets...\n"
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                try:
                    packets = rdpcap(tmp_path)
                    events = generate_events(packets)
                    detected_type = "pcap"
                finally:
                    os.unlink(tmp_path)
            else:
                try:
                    raw = content.decode("utf-8", errors="replace")
                except Exception as e:
                    yield f"[ERROR] Cannot decode file: {e}\n"
                    yield "__RESULT__" + json.dumps({"status": "error", "message": str(e)}) + "\n"
                    return
                yield f"[INFO] Auto-detecting log format...\n"
                if source_type == "auto":
                    detected_type, events = log_ingestor.auto_detect_and_parse(raw, fname)
                else:
                    events = log_ingestor.ingest(source_type, raw)
                    detected_type = source_type

            yield f"[INFO] Detected format: {detected_type} · Events parsed: {len(events)}\n"

            if not events:
                result = {
                    "status": "no_events",
                    "message": "File parsed but no network events extracted.",
                    "detected_type": detected_type,
                    "filename": fname
                }
                yield "[WARN] No events extracted from file\n"
                yield "__RESULT__" + json.dumps(result) + "\n"
                return

            yield "[INFO] Running detection engine...\n"
            incident = detect_incident(events)
            if not incident:
                yield "[INFO] No incident triggered by detection rules\n"
                result = {"status": "no_incident", "events_parsed": len(events), "source_name": sname,
                          "detected_type": detected_type, "filename": fname}
                yield "__RESULT__" + json.dumps(result) + "\n"
                return

            yield f"[ALERT] Incident detected: {incident.get('incident_type')} — severity {incident.get('severity')}\n"

            yield "[INFO] Enriching with threat intelligence...\n"
            threat_intel = enrich_incident(incident)
            incident["threat_intel_verdict"] = threat_intel.get("overall_verdict", "unknown")
            incident["max_threat_score"] = threat_intel.get("max_threat_score", 0.0)
            yield f"[INFO] Threat intel verdict: {threat_intel.get('overall_verdict')}\n"

            yield "[INFO] Enriching asset context...\n"
            asset_ctx = enrich_incident_assets(incident)
            incident["max_asset_criticality"] = asset_ctx.get("max_asset_criticality", "unknown")

            yield "[INFO] Running triage agent...\n"
            verdict = triage_incident(incident)
            yield f"[INFO] Triage decision: {verdict.get('decision')} (confidence {verdict.get('confidence', 0):.2f})\n"

            yield "[INFO] Running investigation agent...\n"
            investigation = investigate_incident(incident, events)
            yield f"[INFO] Hypothesis: {investigation.get('attacker_hypothesis')}\n"

            yield "[INFO] Running decision agent...\n"
            decision = decide(incident, verdict, investigation)
            yield f"[INFO] Decision: {decision.get('action')} — human review: {decision.get('requires_human_review')}\n"

            yield "[INFO] Running response agent...\n"
            response = respond_to_incident(incident, verdict, decision)

            yield "[INFO] Saving case...\n"
            saved_file = case_manager.save_case(
                incident, verdict, investigation, response, sname, decision,
                threat_intel=threat_intel, asset_context=asset_ctx
            )
            case_id = os.path.basename(saved_file).replace(".json", "")
            yield f"[OK] Case saved: {case_id}\n"

            if decision["requires_human_review"]:
                queue_for_review(case_id, incident, verdict, investigation, decision)
                yield "[INFO] Case queued for human review\n"

            with open(saved_file) as f:
                case_data = json.load(f)
            case_data["sla_status"] = case_manager.get_sla_status(case_data)

            result = {
                "status": "case_created", "case_id": case_id, "case": case_data,
                "detected_type": detected_type, "events_parsed": len(events), "filename": fname
            }
            yield "__RESULT__" + json.dumps(result) + "\n"

        except Exception as e:
            yield f"[ERROR] Pipeline failed: {e}\n"
            yield "__RESULT__" + json.dumps({"status": "error", "message": str(e)}) + "\n"

    return StreamingResponse(generate(), media_type="text/plain")


@app.get("/api/ingest/source-types")
def list_source_types():
    return {
        "source_types": [
            {"value": "auto",              "label": "Auto-detect (recommended)"},
            {"value": "generic_csv",       "label": "Generic CSV (any src_ip/dst_ip columns)"},
            {"value": "splunk_stream_csv", "label": "Splunk stream:tcp/udp CSV export"},
            {"value": "aws_vpc",           "label": "AWS VPC Flow Logs"},
            {"value": "gcp_vpc",           "label": "GCP VPC Flow Logs (JSON lines)"},
            {"value": "fw_iptables",       "label": "Firewall — iptables/pf"},
            {"value": "fw_asa",            "label": "Firewall — Cisco ASA"},
            {"value": "siem_cef",          "label": "SIEM — CEF/syslog"},
            {"value": "edr_json",          "label": "EDR — JSON export (CrowdStrike/CB)"},
        ]
    }


# ── Feedback / Rule Tuning ─────────────────────────────────────────────────

@app.get("/api/feedback/rule-performance")
def rule_performance():
    return feedback_loop.get_rule_performance()


# ── Pipeline Trigger (streaming stdout) ───────────────────────────────────

_pipeline_running = False


@app.post("/api/pipeline/run")
async def run_pipeline(background_tasks: BackgroundTasks):
    global _pipeline_running
    if _pipeline_running:
        raise HTTPException(409, "Pipeline already running")
    _pipeline_running = True

    async def stream_output():
        global _pipeline_running
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "main.py",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            async for line in proc.stdout:
                yield line.decode(errors="replace")
            await proc.wait()
            yield f"\n[pipeline] exit code {proc.returncode}\n"
        finally:
            _pipeline_running = False

    return StreamingResponse(stream_output(), media_type="text/plain")


@app.get("/api/pipeline/status")
def pipeline_status():
    return {"running": _pipeline_running}


# ── Frontend ───────────────────────────────────────────────────────────────

@app.get("/")
def serve_index():
    index = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return {"message": "SOC Agent API — see /docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
