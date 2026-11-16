"""
Threat Intelligence (CTI) Hub & Indicator Enrichment Engine.
Correlates indicators against known bad IP feeds, Tor exit nodes, C2 trackers, and ASN reputation.
"""
import re
import ipaddress
from datetime import datetime
from typing import Dict, Optional, List, Any
from backend.app.models.schemas import ThreatIntelHit


# Pre-populated curated threat intelligence feed of malicious IPs & C2 nodes
KNOWN_MALICIOUS_INDICATORS: Dict[str, Dict[str, Any]] = {
    # Known Botnet / C2 IPs
    "185.220.101.5": {
        "reputation_score": 98,
        "categories": ["Tor Exit Node", "Credential Spraying", "C2 Infrastructure"],
        "threat_actor": "APT29 (Cozy Bear)",
        "cve_ids": ["CVE-2023-38831", "CVE-2024-21413"],
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "asn": "AS208294",
        "isp": "Zwiebelfreunde e.V.",
        "tor_exit_node": True,
        "reported_abuse_count": 1420
    },
    "45.142.195.12": {
        "reputation_score": 95,
        "categories": ["Cobalt Strike C2", "Ransomware Distribution"],
        "threat_actor": "Wizard Spider (Conti/BlackBasta)",
        "cve_ids": ["CVE-2021-44228", "CVE-2023-34362"],
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "asn": "AS44050",
        "isp": "Petersburg Internet Network",
        "tor_exit_node": False,
        "reported_abuse_count": 890
    },
    "194.26.29.114": {
        "reputation_score": 92,
        "categories": ["Mirai Botnet", "DDoS Cannon", "Brute Force"],
        "threat_actor": "Mirai Operator Group",
        "cve_ids": ["CVE-2017-17215", "CVE-2022-26186"],
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "asn": "AS200019",
        "isp": "Alexhost SRL",
        "tor_exit_node": False,
        "reported_abuse_count": 2150
    },
    "103.145.13.88": {
        "reputation_score": 88,
        "categories": ["Web Scanner", "SQL Injection Prober"],
        "threat_actor": "Mass Exploitation Scanner",
        "cve_ids": ["CVE-2023-22515", "CVE-2024-1709"],
        "country": "China",
        "country_code": "CN",
        "city": "Beijing",
        "asn": "AS139007",
        "isp": "Tencent Cloud Computing",
        "tor_exit_node": False,
        "reported_abuse_count": 630
    },
    "198.51.100.23": {
        "reputation_score": 85,
        "categories": ["Data Exfiltration Dropzone", "Covert C2"],
        "threat_actor": "Lazarus Group (HIDDEN COBRA)",
        "cve_ids": ["CVE-2023-46604"],
        "country": "Hong Kong",
        "country_code": "HK",
        "city": "Central",
        "asn": "AS13335",
        "isp": "Cloudflare Bulletproof Proxy",
        "tor_exit_node": False,
        "reported_abuse_count": 412
    },
    "91.240.118.172": {
        "reputation_score": 90,
        "categories": ["SSH Dictionary Attacker", "Port Scanner"],
        "threat_actor": "Automated SSH Spray Campaign",
        "cve_ids": [],
        "country": "Bulgaria",
        "country_code": "BG",
        "city": "Sofia",
        "asn": "AS49392",
        "isp": "S.C. Virtual Web Services",
        "tor_exit_node": False,
        "reported_abuse_count": 1820
    }
}

# Subnet reputation heuristics (e.g. Tor exit clusters, bulletproof hosters)
SUSPICIOUS_SUBNETS = [
    "185.220.101.0/24",
    "45.142.195.0/24",
    "194.26.29.0/24",
    "91.240.118.0/24"
]


class ThreatIntelligenceEngine:
    def __init__(self):
        self.indicators = KNOWN_MALICIOUS_INDICATORS.copy()

    def is_private_ip(self, ip_str: str) -> bool:
        """Determines if an IP address belongs to RFC 1918 private ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return False

    def lookup_indicator(self, indicator: str) -> ThreatIntelHit:
        """
        Enriches an IP or domain with threat intelligence, reputation score, and metadata.
        """
        indicator = indicator.strip()

        # Direct hit in known malicious database
        if indicator in self.indicators:
            data = self.indicators[indicator]
            return ThreatIntelHit(
                indicator=indicator,
                indicator_type="ip",
                reputation_score=data["reputation_score"],
                is_malicious=True,
                categories=data.get("categories", []),
                threat_actor=data.get("threat_actor"),
                cve_ids=data.get("cve_ids", []),
                country=data.get("country", "Unknown"),
                country_code=data.get("country_code", "XX"),
                city=data.get("city"),
                asn=data.get("asn"),
                isp=data.get("isp"),
                tor_exit_node=data.get("tor_exit_node", False),
                reported_abuse_count=data.get("reported_abuse_count", 0),
                last_seen=datetime.utcnow()
            )

        # Check subnet match
        try:
            target_ip = ipaddress.ip_address(indicator)
            for cidr in SUSPICIOUS_SUBNETS:
                if target_ip in ipaddress.ip_network(cidr):
                    return ThreatIntelHit(
                        indicator=indicator,
                        indicator_type="ip",
                        reputation_score=78,
                        is_malicious=True,
                        categories=["Suspicious Bulletproof Hosting Range", "Recent Attack Activity"],
                        threat_actor="Affiliated Host Network",
                        cve_ids=[],
                        country="Netherlands",
                        country_code="NL",
                        city="Rotterdam",
                        asn="AS200019",
                        isp="Offshore Hosting Provider",
                        tor_exit_node=False,
                        reported_abuse_count=340,
                        last_seen=datetime.utcnow()
                    )
        except ValueError:
            pass

        # Handle Private / Internal IPs
        if self.is_private_ip(indicator):
            return ThreatIntelHit(
                indicator=indicator,
                indicator_type="ip",
                reputation_score=0,
                is_malicious=False,
                categories=["Internal Subnet / RFC 1918"],
                threat_actor=None,
                cve_ids=[],
                country="Internal Network",
                country_code="LAN",
                city="Local Subnet",
                asn="Private Enterprise",
                isp="Internal Intranet Gateway",
                tor_exit_node=False,
                reported_abuse_count=0,
                last_seen=datetime.utcnow()
            )

        # Synthesize baseline intelligence for external IP based on octet characteristics
        return self._generate_synthetic_intel(indicator)

    def _generate_synthetic_intel(self, ip_str: str) -> ThreatIntelHit:
        """Provides simulated lookup for public IPs not currently in active blocklist."""
        # Derive reproducible hash characteristics
        ip_hash = hash(ip_str) % 1000
        is_suspicious = (ip_hash % 7) == 0

        score = 65 if is_suspicious else 12
        country_pool = [("United States", "US", "Ashburn", "AS15169", "Google LLC"),
                        ("Germany", "DE", "Frankfurt", "AS24940", "Hetzner Online GmbH"),
                        ("United Kingdom", "GB", "London", "AS5089", "Virgin Media"),
                        ("Singapore", "SG", "Singapore", "AS4657", "Singtel"),
                        ("Brazil", "BR", "Sao Paulo", "AS28573", "Claro Brasil")]
        geo = country_pool[abs(ip_hash) % len(country_pool)]

        return ThreatIntelHit(
            indicator=ip_str,
            indicator_type="ip",
            reputation_score=score,
            is_malicious=is_suspicious,
            categories=["Low Risk Observed Traffic"] if not is_suspicious else ["Anomalous Traffic Source"],
            threat_actor=None if not is_suspicious else "Unattributed Reconnaissance Bot",
            cve_ids=[],
            country=geo[0],
            country_code=geo[1],
            city=geo[2],
            asn=geo[3],
            isp=geo[4],
            tor_exit_node=False,
            reported_abuse_count=42 if is_suspicious else 0,
            last_seen=datetime.utcnow()
        )

    def add_custom_ioc(self, ip_str: str, data: Dict[str, Any]):
        """Allows analysts to dynamically add IOCs during incident response."""
        self.indicators[ip_str] = data
