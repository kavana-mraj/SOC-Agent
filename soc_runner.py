import sys
from scapy.all import rdpcap
from detection_engine import generate_events, detect_incident
from triage_agent import triage_incident
from investigation_agent import investigate_incident
from response_agent import respond_to_incident
from case_manager import save_case
from config import PCAP_OPTIONS, ACTIVE_PCAP

def run_soc():
    for name, file_path in PCAP_OPTIONS.items():
        print(f"\n===== Running {name} =====")
        print(f"Using PCAP file: {file_path}")

        packets = rdpcap(file_path)

        events = generate_events(packets)
        incident = detect_incident(events)

        if incident:
            print("\nIncident:\n")
            print(incident)

            verdict = triage_incident(incident)
            print("\nTriage Verdict:\n")
            print(verdict)

            investigation = investigate_incident(incident, events)
            print("\nInvestigation Result:\n")
            print(investigation)

            response = respond_to_incident(incident, verdict)
            print("\nResponse Action:\n")
            print(response)

            saved_file = save_case(incident, verdict, investigation, response, name)
            print("\nCase saved to:\n")
            print(saved_file)

        else:
            print("\nNo incident detected")