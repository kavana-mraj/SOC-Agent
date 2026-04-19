"""Multi-source log ingestor — SIEM, EDR, firewall, cloud log parsers."""

import json
import re
import csv
import logging
from io import StringIO
from typing import Iterator

logger = logging.getLogger(__name__)


def _norm_event(src_ip, dst_ip, proto=None, dst_port=None, extra=None) -> dict:
    e = {"type": "network_connection", "src_ip": src_ip, "dst_ip": dst_ip}
    if proto:
        e["protocol"] = proto.upper()
    if dst_port is not None:
        e["dst_port"] = int(dst_port)
    if extra:
        e.update(extra)
    return e


# ── SIEM (generic CEF / syslog-style) ──────────────────────────────────────

_CEF_RE = re.compile(
    r"src=(?P<src>[^\s]+).*?dst=(?P<dst>[^\s]+)"
    r"(?:.*?proto=(?P<proto>[^\s]+))?"
    r"(?:.*?dpt=(?P<dpt>\d+))?",
    re.IGNORECASE
)

def parse_siem_cef(log_text: str) -> list:
    events = []
    for line in log_text.splitlines():
        m = _CEF_RE.search(line)
        if m:
            events.append(_norm_event(
                m.group("src"), m.group("dst"),
                m.group("proto"), m.group("dpt")
            ))
    return events


# ── Firewall (iptables / pf / Cisco ASA) ───────────────────────────────────

_IPTABLES_RE = re.compile(
    r"SRC=(?P<src>\S+).*?DST=(?P<dst>\S+)"
    r"(?:.*?PROTO=(?P<proto>\S+))?"
    r"(?:.*?DPT=(?P<dpt>\d+))?",
    re.IGNORECASE
)

_ASA_RE = re.compile(
    r"(?P<proto>TCP|UDP|ICMP)\s+(?P<src>\S+)/\d+\s+->\s+(?P<dst>\S+)/(?P<dpt>\d+)",
    re.IGNORECASE
)

def parse_firewall_log(log_text: str, fmt: str = "iptables") -> list:
    events = []
    pattern = _IPTABLES_RE if fmt == "iptables" else _ASA_RE
    for line in log_text.splitlines():
        m = pattern.search(line)
        if m:
            events.append(_norm_event(
                m.group("src"), m.group("dst"),
                m.group("proto") if "proto" in m.groupdict() else None,
                m.group("dpt") if "dpt" in m.groupdict() else None
            ))
    return events


# ── EDR (CrowdStrike / Carbon Black JSON export) ──────────────────────────

def parse_edr_json(json_text: str) -> list:
    """Parse an EDR JSON export — list of connection records."""
    events = []
    try:
        records = json.loads(json_text)
        if isinstance(records, dict):
            records = records.get("events", records.get("connections", [records]))
        for r in records:
            src = r.get("local_address") or r.get("src_ip") or r.get("LocalAddress", "")
            dst = r.get("remote_address") or r.get("dst_ip") or r.get("RemoteAddress", "")
            proto = r.get("protocol") or r.get("Protocol", "TCP")
            port = r.get("remote_port") or r.get("dst_port") or r.get("RemotePort")
            if src and dst:
                events.append(_norm_event(src, dst, proto, port, {"source": "edr"}))
    except json.JSONDecodeError as e:
        logger.warning("EDR JSON parse error: %s", e)
    return events


# ── Cloud logs (AWS VPC Flow / GCP VPC) ──────────────────────────────────

_VPC_COLS = ["version","account-id","interface-id","srcaddr","dstaddr",
             "srcport","dstport","protocol","packets","bytes","start",
             "end","action","log-status"]

_PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}

def parse_aws_vpc_flow(log_text: str) -> list:
    events = []
    reader = csv.DictReader(StringIO(log_text), fieldnames=_VPC_COLS, delimiter=" ")
    for row in reader:
        if row.get("srcaddr") in ("srcaddr", "-") or row.get("action") == "REJECT":
            continue
        proto = _PROTO_MAP.get(row.get("protocol", ""), row.get("protocol", ""))
        events.append(_norm_event(
            row.get("srcaddr", ""), row.get("dstaddr", ""),
            proto, row.get("dstport"),
            {"bytes": row.get("bytes"), "action": row.get("action"), "source": "aws_vpc"}
        ))
    return events


def parse_gcp_vpc_flow(json_text: str) -> list:
    """Parse GCP VPC flow logs (JSON lines)."""
    events = []
    for line in json_text.splitlines():
        try:
            r = json.loads(line)
            conn = r.get("jsonPayload", {}).get("connection", {})
            src = conn.get("src_ip", "")
            dst = conn.get("dest_ip", "")
            proto_num = str(conn.get("protocol", ""))
            proto = _PROTO_MAP.get(proto_num, proto_num)
            port = conn.get("dest_port")
            if src and dst:
                events.append(_norm_event(src, dst, proto, port, {"source": "gcp_vpc"}))
        except Exception:
            continue
    return events


# ── Dispatcher ─────────────────────────────────────────────────────────────

# ── Generic CSV (auto-detect columns) ─────────────────────────────────────

_CSV_COL_ALIASES = {
    "src_ip":   ("src_ip", "src", "source_ip", "sourceip", "source", "src_address",
                 "SrcIP", "SourceIP", "src_ip_address"),
    "dst_ip":   ("dst_ip", "dest_ip", "dst", "destination_ip", "destinationip",
                 "destination", "dest", "DstIP", "DestIP", "dest_ip_address"),
    "dst_port": ("dst_port", "dest_port", "dport", "destination_port", "port",
                 "DstPort", "DestPort"),
    "src_port": ("src_port", "sport", "source_port", "SrcPort"),
    "protocol": ("protocol", "proto", "transport", "Protocol", "Proto"),
}


def _map_cols(header: list) -> dict:
    """Return {canonical: actual_col} for whichever aliases are present."""
    lower_map = {h.lower().strip(): h for h in header}
    mapping = {}
    for canonical, aliases in _CSV_COL_ALIASES.items():
        for a in aliases:
            if a.lower() in lower_map:
                mapping[canonical] = lower_map[a.lower()]
                break
    return mapping


def parse_generic_csv(csv_text: str) -> list:
    """Parse any CSV that has src_ip + dst_ip columns (flexible aliases)."""
    events = []
    reader = csv.DictReader(StringIO(csv_text))
    if not reader.fieldnames:
        return events
    col = _map_cols(list(reader.fieldnames))
    if "src_ip" not in col or "dst_ip" not in col:
        logger.warning("CSV missing src_ip/dst_ip columns. Found: %s", reader.fieldnames)
        return events
    for row in reader:
        src = row.get(col["src_ip"], "").strip()
        dst = row.get(col["dst_ip"], "").strip()
        if not src or not dst or src in ("-", "") or dst in ("-", ""):
            continue
        port = None
        if "dst_port" in col:
            try:
                port = int(row.get(col["dst_port"], "").strip())
            except (ValueError, AttributeError):
                pass
        proto = None
        if "protocol" in col:
            proto = row.get(col["protocol"], "").strip() or None
        extra = {"source": "csv"}
        # carry extra columns as metadata
        for k, v in row.items():
            if k not in (col.get("src_ip"), col.get("dst_ip"),
                         col.get("dst_port"), col.get("protocol")):
                extra[k.strip()] = v
        events.append(_norm_event(src, dst, proto, port, extra))
    logger.info("parse_generic_csv: %d events", len(events))
    return events


def parse_splunk_stream_csv(csv_text: str) -> list:
    """Parse Splunk stream:tcp/udp CSV export from SPL outputcsv."""
    events = []
    reader = csv.DictReader(StringIO(csv_text))
    if not reader.fieldnames:
        return events
    flds = {f.lower().strip(): f for f in reader.fieldnames}

    def get(row, *keys):
        for k in keys:
            v = row.get(flds.get(k, ""), "").strip()
            if v and v != "-":
                return v
        return ""

    for row in reader:
        src = get(row, "src_ip", "src", "src_ip_address")
        dst = get(row, "dest_ip", "dest", "dest_ip_address")
        if not src or not dst:
            continue
        proto = get(row, "transport", "protocol", "proto")
        port_str = get(row, "dest_port", "dst_port", "dport")
        port = None
        try:
            port = int(port_str) if port_str else None
        except ValueError:
            pass
        extra = {"source": "splunk_stream"}
        for k in ("_time", "bytes_in", "bytes_out", "packets_in", "packets_out", "action"):
            v = get(row, k)
            if v:
                extra[k] = v
        events.append(_norm_event(src, dst, proto, port, extra))
    logger.info("parse_splunk_stream_csv: %d events", len(events))
    return events


def auto_detect_and_parse(raw: str, filename: str = "") -> tuple:
    """Guess format from filename/content, return (source_type, events)."""
    fname = filename.lower()
    stripped = raw.strip()

    # JSON → EDR
    if stripped.startswith("{") or stripped.startswith("["):
        return "edr_json", parse_edr_json(raw)

    # CSV detection
    if fname.endswith(".csv") or (stripped and stripped.split("\n")[0].count(",") >= 2):
        # Splunk stream CSV heuristic
        first_line = stripped.split("\n")[0].lower()
        if any(k in first_line for k in ("dest_ip", "dest_port", "transport", "bytes_in")):
            return "splunk_stream_csv", parse_splunk_stream_csv(raw)
        if "srcaddr" in first_line and "dstaddr" in first_line:
            return "aws_vpc", parse_aws_vpc_flow(raw)
        return "generic_csv", parse_generic_csv(raw)

    # Firewall / SIEM text logs
    if "SRC=" in raw and "DST=" in raw:
        return "fw_iptables", parse_firewall_log(raw)
    if re.search(r"TCP\s+\S+/\d+\s+->\s+\S+/\d+", raw):
        return "fw_asa", parse_firewall_log(raw, fmt="asa")
    if "CEF:" in raw or "src=" in raw and "dst=" in raw:
        return "siem_cef", parse_siem_cef(raw)
    if "jsonPayload" in raw:
        return "gcp_vpc", parse_gcp_vpc_flow(raw)

    # Last resort: try generic CSV
    return "unknown_generic_csv", parse_generic_csv(raw)


# ── Dispatcher ─────────────────────────────────────────────────────────────

def ingest(source_type: str, raw: str) -> list:
    """Unified entry point. source_type: siem_cef, fw_iptables, fw_asa, edr_json,
    aws_vpc, gcp_vpc, splunk_stream_csv, generic_csv, auto"""
    if source_type == "auto":
        _, events = auto_detect_and_parse(raw)
        return events
    dispatch = {
        "siem_cef":          parse_siem_cef,
        "fw_iptables":       parse_firewall_log,
        "fw_asa":            lambda t: parse_firewall_log(t, fmt="asa"),
        "edr_json":          parse_edr_json,
        "aws_vpc":           parse_aws_vpc_flow,
        "gcp_vpc":           parse_gcp_vpc_flow,
        "splunk_stream_csv": parse_splunk_stream_csv,
        "generic_csv":       parse_generic_csv,
    }
    parser = dispatch.get(source_type)
    if not parser:
        raise ValueError(f"Unknown source_type: {source_type}. Choose from {list(dispatch)}")
    events = parser(raw)
    logger.info("Ingested %d events from source_type=%s", len(events), source_type)
    return events
