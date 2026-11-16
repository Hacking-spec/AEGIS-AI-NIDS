"""
Signature-based and heuristic intrusion detection rule engine.
Mimics Snort/Suricata rules with fast regex matching for known attack signatures.
"""
import re
from typing import List, Tuple, Dict, Any


class SignatureRule:
    def __init__(self, rule_id: str, name: str, attack_type: str, severity: str, mitre_id: str, pattern: str, description: str):
        self.rule_id = rule_id
        self.name = name
        self.attack_type = attack_type
        self.severity = severity
        self.mitre_id = mitre_id
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.description = description

    def match(self, text: str) -> bool:
        if not text:
            return False
        return bool(self.regex.search(text))


class SignatureEngine:
    def __init__(self):
        self.rules: List[SignatureRule] = []
        self._load_default_signatures()

    def _load_default_signatures(self):
        rule_defs = [
            # SQL Injection Signatures
            ("SIG-SQLI-001", "SQL Injection - Classic Tautology", "Web Exploit / Injection", "HIGH", "T1190",
             r"('|\%27)?\s*(or|and)\s+(\d+=\d+|'?[a-zA-Z0-9_]+'?\s*=\s*'?[a-zA-Z0-9_]+'?)",
             "Detected classic boolean SQL injection tautology (' OR 1=1 or ' OR '1'='1)"),
            
            ("SIG-SQLI-002", "SQL Injection - UNION SELECT Extraction", "Web Exploit / Injection", "CRITICAL", "T1190",
             r"union\s+(all\s+)?select\b",
             "Detected database extraction attempt using UNION SELECT"),

            ("SIG-SQLI-003", "SQL Injection - Blind Sleep / Time-Delay", "Web Exploit / Injection", "HIGH", "T1190",
             r"(waitfor\s+delay|sleep\s*\(\s*\d+\s*\)|pg_sleep)",
             "Detected time-based blind SQL injection command"),

            # Cross-Site Scripting (XSS)
            ("SIG-XSS-001", "Reflected / Stored XSS Script Tag", "Web Exploit / Injection", "MEDIUM", "T1059.007",
             r"<\s*script\b[^>]*>.*<\s*/\s*script\s*>",
             "Detected embedded executable JavaScript tag"),

            ("SIG-XSS-002", "Event-Handler Inline XSS Vector", "Web Exploit / Injection", "MEDIUM", "T1059.007",
             r"on(error|load|click|mouseover|focus)\s*=\s*['\"]?[^'\">]+",
             "Detected HTML attribute event handler script execution"),

            # Command Injection & Remote Code Execution (RCE)
            ("SIG-RCE-001", "Remote OS Command Injection Chaining", "Web Exploit / Injection", "CRITICAL", "T1059",
             r"(;|\&\&|\|\|)\s*(cat\s+/etc/(passwd|shadow)|whoami|id|powershell|cmd\.exe|/bin/sh|wget\s|curl\s)",
             "Detected remote OS shell command execution payload"),

            ("SIG-LOG4J-001", "Log4Shell JNDI Lookup Exploit", "Web Exploit / Injection", "CRITICAL", "T1190",
             r"\$\{\s*jndi\s*:(ldap|rmi|dns|nis)\s*://",
             "Detected CVE-2021-44228 Log4j JNDI remote code execution string"),

            # Directory Traversal / LFI
            ("SIG-LFI-001", "Path / Directory Traversal Attempt", "Web Exploit / Injection", "HIGH", "T1083",
             r"(\.\./|\.\.\\|\%2e\%2e/|\%2e\%2e\\){2,}",
             "Detected repeated directory traversal sequence to escape web root"),

            # C2 & Botnet Beacons
            ("SIG-C2-001", "Cobalt Strike / Metasploit Beacon Pattern", "Botnet C2 Beaconing", "CRITICAL", "T1071.001",
             r"(/api/v\d+/beacon|/submit\.php\?id=|/activity\?user=|user-agent:\s*(curl|python-requests|go-http-client|mimikatz))",
             "Detected known default Cobalt Strike or automated C2 beaconing pattern"),

            ("SIG-DNS-TUN-001", "DNS Tunneling / Data Exfiltration Signature", "Data Exfiltration", "HIGH", "T1048",
             r"([a-f0-9]{32,}\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9+/=]{20,}\.ns[0-9]*)",
             "Detected long hex or base64 encoded subdomain indicative of DNS tunneling"),

            # Recon & Scanning signatures
            ("SIG-SCAN-001", "Nmap Scripting Engine Probe", "Port Scan / Reconnaissance", "MEDIUM", "T1046",
             r"(nmap\s+nse|masscan|zgrab|nikto|sqlmap|acunetix)",
             "Detected known reconnaissance scanner user-agent or probe header"),

            # Brute force signatures
            ("SIG-BRUTE-001", "SSH / FTP Credential Spray Pattern", "Credential Brute Force", "HIGH", "T1110.001",
             r"(admin:admin|root:root|guest:guest|test:123456|password123)",
             "Detected dictionary credential spray attempt in payload")
        ]

        for r_id, name, atype, sev, mitre, pat, desc in rule_defs:
            self.rules.append(SignatureRule(r_id, name, atype, sev, mitre, pat, desc))

    def evaluate_payload(self, payload: str) -> List[Dict[str, Any]]:
        """Evaluates raw payload or request string against signature database."""
        matches = []
        if not payload:
            return matches

        for rule in self.rules:
            if rule.match(payload):
                matches.append({
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "attack_type": rule.attack_type,
                    "severity": rule.severity,
                    "mitre_id": rule.mitre_id,
                    "description": rule.description
                })
        return matches

    def check_flow_heuristics(self, flow) -> List[Dict[str, Any]]:
        """Evaluates protocol flags, error rates, and port heuristics."""
        matches = []
        
        # Check SYN Flood heuristics
        if getattr(flow, 'flag', '') == 'S0' and getattr(flow, 'serror_rate', 0.0) > 0.8:
            matches.append({
                "rule_id": "HEUR-DOS-001",
                "name": "High Volume Half-Open SYN Flood",
                "attack_type": "DDoS / DoS Flood",
                "severity": "CRITICAL",
                "mitre_id": "T1498.001",
                "description": f"Excessive SYN without ACK (serror_rate: {flow.serror_rate:.2f}) indicates TCP SYN flood"
            })

        # Check Port Scanning heuristics
        if getattr(flow, 'diff_srv_rate', 0.0) > 0.7 and getattr(flow, 'dst_host_count', 0) > 50:
            matches.append({
                "rule_id": "HEUR-SCAN-001",
                "name": "Horizontal / Vertical Port Scan Pattern",
                "attack_type": "Port Scan / Reconnaissance",
                "severity": "MEDIUM",
                "mitre_id": "T1046",
                "description": "High ratio of different services contacted across target hosts indicates scanning"
            })

        # Check Abnormal outbound data volume (Data Exfiltration)
        if getattr(flow, 'src_bytes', 0) > 5_000_000 and getattr(flow, 'dst_bytes', 0) < 5_000:
            matches.append({
                "rule_id": "HEUR-EXFIL-001",
                "name": "Massive Asymmetric Outbound Exfiltration",
                "attack_type": "Data Exfiltration",
                "severity": "HIGH",
                "mitre_id": "T1048",
                "description": f"Outbound byte volume ({flow.src_bytes} bytes) dwarfs inbound acknowledgment"
            })

        # Check Brute Force heuristics
        if getattr(flow, 'dst_port', 0) in (22, 21, 3389) and getattr(flow, 'rerror_rate', 0.0) > 0.75:
            matches.append({
                "rule_id": "HEUR-BRUTE-001",
                "name": "Rapid Service Connection Rejections (Brute Force)",
                "attack_type": "Credential Brute Force",
                "severity": "HIGH",
                "mitre_id": "T1110",
                "description": f"Target port {flow.dst_port} experiencing extreme rejection rate ({flow.rerror_rate:.2f})"
            })

        return matches
