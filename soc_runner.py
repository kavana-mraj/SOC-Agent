from scapy.all import rdpcap
from detection_engine import generate_events, detect_incident
from triage_agent import triage_incident
from investigation_agent import investigate_incident
from decision_agent import decide
from response_agent import respond_to_incident
from human_review import queue_for_review
from case_manager import save_case
from threat_intel import enrich_incident
from asset_context import enrich_incident_assets
from config import PCAP_OPTIONS


def _deduplicate(incidents: list) -> list:
    """Drop duplicate incidents — same type + src_ip within a run."""
    seen = set()
    unique = []
    for inc in incidents:
        key = (inc.get("incident_type"), inc.get("src_ip"))
        if key not in seen:
            seen.add(key)
            unique.append(inc)
    return unique


def run_soc(pcap_options=None):
    if pcap_options is None:
        pcap_options = PCAP_OPTIONS

    all_incidents = []

    # Phase 1: detect all incidents across all PCAPs
    pcap_data = {}
    for name, file_path in pcap_options.items():
        print(f"\n===== Running {name} =====")
        print(f"PCAP: {file_path}")

        packets = rdpcap(file_path)
        events = generate_events(packets)
        incident = detect_incident(events)

        if not incident:
            print("No incident detected")
            continue

        print(f"\nIncident: {incident.get('incident_type')} severity={incident.get('severity')}")
        all_incidents.append(incident)
        pcap_data[name] = {"events": events, "incident": incident}

    # Phase 2: deduplicate correlated incidents
    unique_incidents = _deduplicate(all_incidents)
    if len(unique_incidents) < len(all_incidents):
        print(f"\n[dedup] Reduced {len(all_incidents)} → {len(unique_incidents)} unique incidents")

    # Phase 3: run pipeline per unique incident
    for name, data in pcap_data.items():
        incident = data["incident"]
        events = data["events"]

        if incident not in unique_incidents:
            print(f"\n[dedup] Skipping duplicate incident for {name}")
            continue

        print(f"\n----- Pipeline: {name} -----")

        # Threat intel enrichment
        print("Enriching with threat intel...")
        threat_intel = enrich_incident(incident)
        incident["threat_intel_verdict"] = threat_intel.get("overall_verdict", "unknown")
        incident["max_threat_score"] = threat_intel.get("max_threat_score", 0.0)
        print(f"  Threat intel: verdict={threat_intel.get('overall_verdict')} score={threat_intel.get('max_threat_score')}")

        # Asset context enrichment
        print("Enriching with asset context...")
        asset_ctx = enrich_incident_assets(incident)
        incident["max_asset_criticality"] = asset_ctx.get("max_asset_criticality", "unknown")
        print(f"  Asset criticality: {asset_ctx.get('max_asset_criticality')}")

        # Triage
        verdict = triage_incident(incident)
        print(f"Triage: decision={verdict['decision']} severity={verdict['severity']} confidence={verdict.get('confidence', 0):.2f}")

        # Investigation
        investigation = investigate_incident(incident, events)
        print(f"Investigation: hypothesis={investigation['attacker_hypothesis']} confidence={investigation.get('confidence', 0):.2f}")

        # Decision
        decision = decide(incident, verdict, investigation)
        print(f"Decision: action={decision['action']} confidence={decision['confidence']:.2f} auto={decision['auto_respond']}")

        # Response
        response = respond_to_incident(incident, verdict, decision)
        print(f"Response: {response['action']} status={response['status']}")

        # Save case
        saved_file = save_case(
            incident, verdict, investigation, response, name, decision,
            threat_intel=threat_intel, asset_context=asset_ctx
        )
        print(f"Case saved: {saved_file} tier={verdict.get('analyst_tier', 'computed-in-case_manager')}")

        # Human review queue
        if decision["requires_human_review"]:
            case_id = saved_file.split("/")[-1].replace(".json", "")
            queue_for_review(case_id, incident, verdict, investigation, decision)
            print(f"Queued for human review: {case_id}")
        else:
            print("Autonomous response executed — no human review needed")
