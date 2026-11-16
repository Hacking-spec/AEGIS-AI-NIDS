"""
Automated Incident Response & SOAR Playbook Engine.
Generates multi-vendor mitigation commands, firewall rules, and host isolation scripts.
"""
from typing import Dict, Any, List
from datetime import datetime


class PlaybookEngine:
    @staticmethod
    def generate_firewall_rules(ip: str, port: int = 0, protocol: str = "tcp") -> Dict[str, str]:
        """
        Generates cross-platform firewall blocking commands for instant deployment.
        """
        rules = {
            "iptables": f"sudo iptables -I INPUT -s {ip} -j DROP && sudo iptables -I FORWARD -s {ip} -j DROP",
            "nftables": f"sudo nft add rule inet filter input ip saddr {ip} counter drop",
            "windows_netsh": f'netsh advfirewall firewall add rule name="AegisBlock_{ip}" dir=in action=block remoteip={ip}',
            "windows_powershell": f'New-NetFirewallRule -DisplayName "Aegis_Block_{ip}" -Direction Inbound -Action Block -RemoteAddress {ip}',
            "cisco_ios": f"access-list 101 deny ip host {ip} any\naccess-list 101 permit ip any any",
            "aws_security_group": f'aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol {protocol} --port {port if port > 0 else 0}-{port if port > 0 else 65535} --cidr {ip}/32',
            "pfsense_xml": f'<rule><type>block</type><interface>wan</interface><source><address>{ip}</address></source></rule>'
        }
        return rules

    @staticmethod
    def generate_host_isolation_script(host_ip: str) -> Dict[str, str]:
        """
        Generates script to isolate compromised internal host from intranet.
        """
        return {
            "linux_quarantine": f"""#!/bin/bash
# Aegis Automated Host Containment for {host_ip}
echo "[!] Isolating {host_ip} from local subnet..."
sudo iptables -F
sudo iptables -A INPUT -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -s 192.168.1.10 -j ACCEPT  # Allow SOC Admin Bastion
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -d 192.168.1.10 -j ACCEPT
sudo iptables -A OUTPUT -j DROP
echo "[✓] Host isolation complete. Only SOC bastion connection permitted."
""",
            "windows_quarantine": f"""# Aegis Windows Isolation Script for {host_ip}
Write-Host "[!] Isolating {host_ip} from local network..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "Aegis_Total_Isolation" -Direction Inbound -Action Block
New-NetFirewallRule -DisplayName "Aegis_Outbound_Isolation" -Direction Outbound -Action Block
# Allow SOC Bastion on port 5985/5986 (WinRM)
New-NetFirewallRule -DisplayName "Aegis_Allow_SOC" -Direction Inbound -Action Allow -RemoteAddress "192.168.1.10"
Write-Host "[✓] Host isolated successfully." -ForegroundColor Green
"""
        }

    @staticmethod
    def get_playbook_recommendation(attack_type: str, severity: str, src_ip: str) -> Dict[str, Any]:
        """
        Returns structured playbook workflow recommendation based on attack type and severity.
        """
        if "DDoS" in attack_type:
            return {
                "playbook_id": "PB-DDOS-01",
                "name": "Distributed Denial of Service Neutralization",
                "steps": [
                    f"Null-route attacking IP {src_ip} at edge gateway",
                    "Enable TCP SYN cookies on border firewalls",
                    "Engage CDN / Upstream DDoS scrubbers",
                    "Export NetFlow records for forensic attribution"
                ],
                "recommended_action": "QUARANTINE_IP_AND_RATE_LIMIT",
                "automation_level": "AUTOMATIC" if severity == "CRITICAL" else "MANUAL_APPROVAL"
            }
        elif "Brute Force" in attack_type:
            return {
                "playbook_id": "PB-AUTH-02",
                "name": "Administrative Credential Attack Mitigation",
                "steps": [
                    f"Temporary 24h IP drop for source {src_ip}",
                    "Trigger password reset for targeted account identities",
                    "Verify MFA enforcement across all external entrypoints",
                    "Log failed authentication attempts to SIEM"
                ],
                "recommended_action": "QUARANTINE_IP",
                "automation_level": "AUTOMATIC"
            }
        elif "Web Exploit" in attack_type or "SQL" in attack_type:
            return {
                "playbook_id": "PB-APP-03",
                "name": "Web Application Exploit Containment",
                "steps": [
                    f"Deploy WAF custom block rule for IP {src_ip}",
                    "Inspect database query logs for unauthorized data disclosure",
                    "Sanitize and patch vulnerable URI endpoint parameters",
                    "Generate STIX 2.1 Threat Report for threat sharing"
                ],
                "recommended_action": "BLOCK_IP_AND_WAF_INSPECT",
                "automation_level": "AUTOMATIC"
            }
        elif "C2" in attack_type or "Beacon" in attack_type:
            return {
                "playbook_id": "PB-C2-04",
                "name": "Command & Control / Botnet Severance",
                "steps": [
                    f"Sever outbound C2 channel to {src_ip} immediately",
                    "Identify infected internal endpoints connecting to C2 node",
                    "Initiate memory forensic dump on compromised victim system",
                    "Broadcast IOC to EDR agents for enterprise-wide hunt"
                ],
                "recommended_action": "ISOLATE_HOST_AND_BLOCK_C2",
                "automation_level": "AUTOMATIC"
            }
        elif "Exfiltration" in attack_type:
            return {
                "playbook_id": "PB-EXFIL-05",
                "name": "Data Loss Prevention & Exfiltration Interception",
                "steps": [
                    f"Immediately terminate active egress connections to {src_ip}",
                    "Revoke session tokens and credentials accessed in past 4 hours",
                    "Audit data volume transferred to external dropzone",
                    "Preserve network flow forensic PCAP"
                ],
                "recommended_action": "TERMINATE_CONNECTION_AND_BLOCK",
                "automation_level": "AUTOMATIC"
            }
        else:
            return {
                "playbook_id": "PB-ANOM-06",
                "name": "Zero-Day Anomaly Investigation",
                "steps": [
                    f"Rate-limit traffic from {src_ip}",
                    "Perform deep packet inspection on unclassified payload",
                    "Submit telemetry to AI retraining queue",
                    "Notify On-Duty Threat Hunter"
                ],
                "recommended_action": "RATE_LIMIT_AND_INSPECT",
                "automation_level": "MANUAL_APPROVAL"
            }
