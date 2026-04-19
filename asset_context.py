"""Asset context enrichment — criticality, owner, and recent activity per IP/host."""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

ASSET_DB_FILE = os.getenv("ASSET_DB_FILE", "asset_db.json")

_DEFAULT_ASSETS = {
    "192.168.1.1":  {"hostname": "gateway-01",    "owner": "network-ops",  "criticality": "high",   "role": "gateway"},
    "192.168.1.10": {"hostname": "workstation-10", "owner": "john.doe",     "criticality": "medium", "role": "workstation"},
    "192.168.1.20": {"hostname": "server-web-01",  "owner": "web-team",     "criticality": "critical","role": "web_server"},
    "192.168.1.30": {"hostname": "db-prod-01",     "owner": "dba-team",     "criticality": "critical","role": "database"},
    "10.0.0.5":     {"hostname": "dc-01",          "owner": "it-ops",       "criticality": "critical","role": "domain_controller"},
    "8.8.8.8":      {"hostname": "google-dns",     "owner": "Google",       "criticality": "low",    "role": "external_dns"},
}


def _load_asset_db() -> dict:
    if os.path.exists(ASSET_DB_FILE):
        try:
            with open(ASSET_DB_FILE) as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load asset DB: %s", e)
    return _DEFAULT_ASSETS


def _load_recent_activity(ip: str) -> list:
    """Pull last N case files involving this IP as a simple activity log."""
    from glob import glob
    activity = []
    for path in sorted(glob("cases/case_*.json"), reverse=True)[:50]:
        try:
            with open(path) as f:
                case = json.load(f)
            inc = case.get("incident", {})
            if inc.get("src_ip") == ip or inc.get("dst_ip") == ip:
                activity.append({
                    "case_id": os.path.basename(path).replace(".json", ""),
                    "timestamp": case.get("timestamp"),
                    "incident_type": inc.get("incident_type"),
                    "severity": inc.get("severity")
                })
                if len(activity) >= 5:
                    break
        except Exception:
            continue
    return activity


def get_asset_context(ip: str) -> dict:
    db = _load_asset_db()
    asset = db.get(ip, {})
    recent = _load_recent_activity(ip)

    return {
        "ip": ip,
        "hostname": asset.get("hostname", "unknown"),
        "owner": asset.get("owner", "unknown"),
        "criticality": asset.get("criticality", "unknown"),
        "role": asset.get("role", "unknown"),
        "known_asset": bool(asset),
        "recent_incidents": recent,
        "recent_incident_count": len(recent)
    }


def enrich_incident_assets(incident: dict) -> dict:
    src_ctx = get_asset_context(incident.get("src_ip", ""))
    dst_ctx = get_asset_context(incident.get("dst_ip", ""))

    max_crit = max(
        {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(src_ctx["criticality"], 0),
        {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(dst_ctx["criticality"], 0)
    )
    crit_label = ["unknown", "low", "medium", "high", "critical"][max_crit]

    return {
        "src_asset": src_ctx,
        "dst_asset": dst_ctx,
        "max_asset_criticality": crit_label
    }
