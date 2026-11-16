"""
Command Line Interface (CLI) for Aegis AI-NIDS and Sentinel Threat Intelligence.
"""
import sys
import argparse
import json
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.intelligence.threat_intel import ThreatIntelligenceEngine
from backend.app.intelligence.playbook_engine import PlaybookEngine
from backend.app.traffic.simulator import TrafficSimulator
from backend.app.traffic.pcap_processor import PCAPProcessor
from backend.app.services.detection_service import detection_service
from train_models import train_and_evaluate


def main():
    parser = argparse.ArgumentParser(
        description="Aegis AI-NIDS: AI-Based Intrusion Detection & Threat Intelligence CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: train
    subparsers.add_parser("train", help="Retrain AI Supervised and AutoEncoder models")

    # Command: lookup
    lookup_parser = subparsers.add_parser("lookup", help="Query Cyber Threat Intelligence on an IP")
    lookup_parser.add_argument("indicator", type=str, help="IP address or domain to analyze")

    # Command: simulate
    sim_parser = subparsers.add_parser("simulate", help="Simulate attack vectors and evaluate with AI")
    sim_parser.add_argument(
        "--type",
        choices=["ddos_syn", "port_scan_nmap", "ssh_brute", "sqli_web", "c2_beacon", "exfiltration", "normal"],
        default="ddos_syn",
        help="Attack vector profile to simulate"
    )
    sim_parser.add_argument("--count", type=int, default=5, help="Number of flows to generate")
    sim_parser.add_argument("--target", type=str, default="192.168.1.100", help="Target IP address")

    # Command: scan-pcap
    pcap_parser = subparsers.add_parser("scan-pcap", help="Parse and analyze a .pcap network capture file")
    pcap_parser.add_argument("file", type=str, help="Path to .pcap file")

    # Command: firewall
    fw_parser = subparsers.add_parser("firewall", help="Generate multi-vendor firewall block commands for an IP")
    fw_parser.add_argument("ip", type=str, help="IP address to generate block rules for")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "train":
        train_and_evaluate()

    elif args.command == "lookup":
        ti = ThreatIntelligenceEngine()
        res = ti.lookup_indicator(args.indicator)
        print("\n" + "=" * 60)
        print(f"  THREAT INTELLIGENCE DOSSIER: {args.indicator}")
        print("=" * 60)
        print(f"  Reputation Score : {res.reputation_score}/100")
        print(f"  Malicious Status : {'[!] CONFIRMED MALICIOUS' if res.is_malicious else '[✓] CLEAN / LOW RISK'}")
        print(f"  Threat Categories: {', '.join(res.categories) if res.categories else 'None'}")
        print(f"  Attributed Actor : {res.threat_actor or 'None'}")
        print(f"  Associated CVEs  : {', '.join(res.cve_ids) if res.cve_ids else 'None'}")
        print(f"  Geolocation      : {res.city or 'N/A'}, {res.country} ({res.country_code})")
        print(f"  Network ASN/ISP  : {res.asn or 'N/A'} - {res.isp or 'N/A'}")
        print(f"  Tor Exit Node    : {'YES' if res.tor_exit_node else 'NO'}")
        print(f"  Abuse Reports    : {res.reported_abuse_count}")
        print("=" * 60 + "\n")

    elif args.command == "simulate":
        print(f"\n[+] Simulating {args.count} flows of type '{args.type}' targeting {args.target}...")
        flows = TrafficSimulator.generate_batch(attack_type=args.type, count=args.count, target_ip=args.target)
        for i, flow in enumerate(flows, 1):
            detection = detection_service.ensemble.evaluate_flow(flow)
            status_tag = f"[{detection.severity.value}]"
            print(f"  [{i}/{args.count}] {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} ({flow.protocol.value})")
            print(f"        Classification : {detection.predicted_class.value} (Confidence: {detection.confidence*100:.1f}%)")
            print(f"        Threat Score   : {detection.threat_score}/100 {status_tag} | Anomaly Score: {detection.anomaly_score:.3f}")
            if detection.signature_matches:
                print(f"        Signatures     : {', '.join(detection.signature_matches)}")
            print(f"        Recommended    : {detection.recommended_action}\n")

    elif args.command == "scan-pcap":
        path = Path(args.file)
        if not path.exists():
            print(f"[ERROR] File not found: {path}")
            sys.exit(1)
        print(f"[+] Parsing PCAP binary: {path}...")
        flows = PCAPProcessor.parse_pcap_file(path)
        print(f"[✓] Extracted {len(flows)} network flows. Running AI Intrusion Detection...")
        threat_count = 0
        for flow in flows:
            detection = detection_service.ensemble.evaluate_flow(flow)
            if detection.threat_score >= 25.0:
                threat_count += 1
                print(f"  [ALERT] {flow.src_ip} -> {flow.dst_ip} | {detection.predicted_class.value} | Threat Score: {detection.threat_score}")
        print(f"\n[✓] Analysis Complete: {len(flows)} flows analyzed, {threat_count} threats detected.")

    elif args.command == "firewall":
        rules = PlaybookEngine.generate_firewall_rules(args.ip)
        print(f"\n[+] Cross-Platform Mitigation Rules for {args.ip}:")
        for platform, rule in rules.items():
            print(f"\n--- {platform.upper()} ---")
            print(rule)
        print()


if __name__ == "__main__":
    main()
