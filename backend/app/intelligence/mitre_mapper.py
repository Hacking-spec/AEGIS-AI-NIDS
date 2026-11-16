"""
MITRE ATT&CK Matrix Mapping Engine.
Maps detection classifications, heuristic indicators, and signatures to MITRE Enterprise tactics & techniques.
"""
from typing import List, Dict, Optional
from backend.app.models.schemas import AttackType, MitreTechnique


MITRE_DATABASE: Dict[str, Dict[str, str]] = {
    "T1046": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable attack surfaces.",
        "mitigation": "Disable unnecessary services, restrict external network exposure using edge firewalls, and deploy automated port-scan detection.",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1498": {
        "technique_id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted systems or networks.",
        "mitigation": "Deploy upstream DDoS mitigation services, enable TCP SYN cookies, apply rate limiting, and drop malformed packet streams.",
        "url": "https://attack.mitre.org/techniques/T1498/"
    },
    "T1498.001": {
        "technique_id": "T1498.001",
        "name": "Direct Network Flood (SYN/UDP Flood)",
        "tactic": "Impact",
        "description": "Adversaries direct overwhelming network traffic (such as TCP SYN floods or UDP reflection) at a victim to saturate link bandwidth.",
        "mitigation": "Implement upstream BGP Anycast scrubbing, TCP SYN proxying on firewalls, and automated dynamic IP null-routing.",
        "url": "https://attack.mitre.org/techniques/T1498/001/"
    },
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt authentication on network services like SSH, RDP, or FTP.",
        "mitigation": "Enforce strong multi-factor authentication (MFA), account lockout thresholds, and fail2ban style automated IP quarantining.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "name": "Password Guessing & Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries systematically guess passwords or test a small set of commonly used passwords across many user accounts.",
        "mitigation": "Implement adaptive authentication, restrict exposed administrative ports to dedicated VPN bastions, and audit authentication failures.",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "T1190": {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing web software (e.g. SQL Injection, Path Traversal, Log4Shell).",
        "mitigation": "Deploy Web Application Firewalls (WAF), validate and sanitize all user input with parameterized queries, and maintain timely patch management.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "T1059": {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, CMD) to execute malicious commands on victim hosts.",
        "mitigation": "Enforce script block logging, disable PowerShell v2, apply constrained language mode, and restrict binary execution with AppLocker.",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "T1059.007": {
        "technique_id": "T1059.007",
        "name": "JavaScript Execution / Cross-Site Scripting",
        "tactic": "Execution",
        "description": "Adversaries execute malicious client-side JavaScript to hijack user sessions, steal credentials, or pivot deeper into networks.",
        "mitigation": "Apply Content Security Policy (CSP) headers, encode HTML outputs, and implement strict cookie attributes (HttpOnly, SameSite=Strict).",
        "url": "https://attack.mitre.org/techniques/T1059/007/"
    },
    "T1071": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": "Adversaries communicate using application layer protocols (HTTP, HTTPS, DNS) to blend C2 traffic with normal network operations.",
        "mitigation": "Perform deep packet inspection (DPI), inspect SSL/TLS sessions with certificate validation, and analyze network flow jitter/periodicity.",
        "url": "https://attack.mitre.org/techniques/T1071/"
    },
    "T1071.001": {
        "technique_id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "description": "Adversaries communicate using standard HTTP/HTTPS channels to bypass simple firewall boundary filters.",
        "mitigation": "Inspect HTTP headers, monitor abnormal user-agents, block newly registered domains, and alert on periodic beacon timing intervals.",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1048": {
        "technique_id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an unencrypted or alternative protocol such as DNS, ICMP, or high-port TCP.",
        "mitigation": "Enforce egress filtering, inspect DNS queries for large entropy payloads, and apply Data Loss Prevention (DLP) packet monitoring.",
        "url": "https://attack.mitre.org/techniques/T1048/"
    },
    "T1083": {
        "technique_id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries enumerate files and directories or search specific locations for sensitive data using directory traversal.",
        "mitigation": "Harden web server root directories, apply strict access permissions, and filter path traversal traversal sequences (../).",
        "url": "https://attack.mitre.org/techniques/T1083/"
    },
    "T1205": {
        "technique_id": "T1205",
        "name": "Traffic Signaling / Port Knocking (Anomalous Flow)",
        "tactic": "Defense Evasion",
        "description": "Adversaries use non-standard communication patterns to signal compromised hosts or bypass boundary defenses.",
        "mitigation": "Employ behavioral anomaly detection to surface statistical flow deviations from established baselines.",
        "url": "https://attack.mitre.org/techniques/T1205/"
    }
}

ATTACK_TYPE_TO_MITRE = {
    AttackType.PORT_SCAN: ["T1046"],
    AttackType.DDOS: ["T1498", "T1498.001"],
    AttackType.BRUTE_FORCE: ["T1110", "T1110.001"],
    AttackType.WEB_ATTACK: ["T1190", "T1059.007"],
    AttackType.C2_BEACON: ["T1071", "T1071.001"],
    AttackType.EXFILTRATION: ["T1048"],
    AttackType.ZERO_DAY_ANOMALY: ["T1205"]
}


class MitreMapper:
    @staticmethod
    def get_techniques_for_attack(attack_type: AttackType, explicit_mitre_ids: Optional[List[str]] = None) -> List[MitreTechnique]:
        """Resolves MITRE ATT&CK techniques associated with an attack type or rule matches."""
        technique_ids = set()
        
        if explicit_mitre_ids:
            for m_id in explicit_mitre_ids:
                technique_ids.add(m_id)

        default_ids = ATTACK_TYPE_TO_MITRE.get(attack_type, [])
        for d_id in default_ids:
            technique_ids.add(d_id)

        results = []
        for tid in technique_ids:
            # Check for parent technique if sub-technique missing
            info = MITRE_DATABASE.get(tid)
            if not info and "." in tid:
                parent_id = tid.split(".")[0]
                info = MITRE_DATABASE.get(parent_id)

            if info:
                results.append(MitreTechnique(
                    technique_id=info["technique_id"],
                    name=info["name"],
                    tactic=info["tactic"],
                    description=info["description"],
                    mitigation=info["mitigation"],
                    url=info["url"]
                ))

        return results

    @staticmethod
    def get_all_matrix_techniques() -> List[Dict[str, str]]:
        """Returns the full MITRE database for dashboard matrix visualization."""
        return list(MITRE_DATABASE.values())
