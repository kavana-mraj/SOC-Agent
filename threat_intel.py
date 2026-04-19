import os
import requests
import logging

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_KEY = os.getenv("OTX_API_KEY", "")

PRIVATE_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1"
)

def _is_private(ip: str) -> bool:
    return any(ip.startswith(r) for r in PRIVATE_RANGES)


def _query_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"source": "abuseipdb", "error": "no_api_key", "score": 0, "reports": 0}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=5
        )
        data = resp.json().get("data", {})
        return {
            "source": "abuseipdb",
            "score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "is_whitelisted": data.get("isWhitelisted", False),
            "last_reported": data.get("lastReportedAt")
        }
    except Exception as e:
        logger.warning("AbuseIPDB query failed for %s: %s", ip, e)
        return {"source": "abuseipdb", "error": str(e), "score": 0, "reports": 0}


def _query_otx(ip: str) -> dict:
    if not OTX_KEY:
        return {"source": "otx", "error": "no_api_key", "malicious": False, "pulse_count": 0}
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=5
        )
        data = resp.json()
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])
        tags = []
        for p in pulses[:3]:
            tags.extend(p.get("tags", []))
        return {
            "source": "otx",
            "pulse_count": pulse_count,
            "malicious": pulse_count > 0,
            "tags": list(set(tags))[:10],
            "country": data.get("country_name", "")
        }
    except Exception as e:
        logger.warning("OTX query failed for %s: %s", ip, e)
        return {"source": "otx", "error": str(e), "malicious": False, "pulse_count": 0}


def enrich_ip(ip: str) -> dict:
    if _is_private(ip):
        return {
            "ip": ip,
            "private": True,
            "abuseipdb": None,
            "otx": None,
            "threat_score": 0,
            "verdict": "private"
        }

    abuse = _query_abuseipdb(ip)
    otx = _query_otx(ip)

    abuse_score = abuse.get("score", 0)
    otx_score = 50 if otx.get("malicious") else 0

    threat_score = round((abuse_score * 0.7 + otx_score * 0.3), 1)

    if threat_score >= 70:
        verdict = "malicious"
    elif threat_score >= 30:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "ip": ip,
        "private": False,
        "abuseipdb": abuse,
        "otx": otx,
        "threat_score": threat_score,
        "verdict": verdict
    }


def enrich_incident(incident: dict) -> dict:
    src = incident.get("src_ip", "")
    dst = incident.get("dst_ip", "")

    enrichment = {}
    if src:
        enrichment["src_ip"] = enrich_ip(src)
    if dst:
        enrichment["dst_ip"] = enrich_ip(dst)

    max_score = max(
        enrichment.get("src_ip", {}).get("threat_score", 0),
        enrichment.get("dst_ip", {}).get("threat_score", 0)
    )
    enrichment["max_threat_score"] = max_score
    enrichment["overall_verdict"] = (
        "malicious" if max_score >= 70 else
        "suspicious" if max_score >= 30 else
        "clean"
    )

    return enrichment
