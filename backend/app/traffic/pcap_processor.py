"""
Pure Python Libpcap Binary Reader & Writer.
Enables parsing and exporting network traffic PCAP files without external WinPcap/Npcap driver dependencies.
"""
import struct
import socket
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime

from backend.app.models.schemas import NetworkFlow, ProtocolType


# PCAP Constants
PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1


class PCAPProcessor:
    @staticmethod
    def create_pcap_file(filepath: Path, packets: List[Dict[str, Any]]):
        """
        Writes a list of synthetic or captured packets into a standard Libpcap binary file.
        Compatible with Wireshark, tcpdump, and Zeek.
        """
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "wb") as f:
            # 24-byte PCAP Global Header
            # Magic (4B), Maj (2B), Min (2B), Zone (4B), SigFigs (4B), SnapLen (4B), Network (4B)
            global_hdr = struct.pack(
                "=IHHiIII",
                PCAP_MAGIC_MICROSECONDS,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,
                0,
                65535,
                LINKTYPE_ETHERNET
            )
            f.write(global_hdr)

            for pkt in packets:
                ts_sec = int(pkt.get("timestamp", time.time()))
                ts_usec = int((pkt.get("timestamp", time.time()) - ts_sec) * 1_000_000)

                raw_bytes = PCAPProcessor._craft_raw_packet(
                    src_ip=pkt.get("src_ip", "192.168.1.50"),
                    dst_ip=pkt.get("dst_ip", "192.168.1.100"),
                    src_port=pkt.get("src_port", 44321),
                    dst_port=pkt.get("dst_port", 80),
                    proto=pkt.get("protocol", "TCP"),
                    payload=pkt.get("payload", b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
                )

                pkt_len = len(raw_bytes)
                # 16-byte Packet Header: ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
                pkt_hdr = struct.pack("=IIII", ts_sec, ts_usec, pkt_len, pkt_len)
                f.write(pkt_hdr)
                f.write(raw_bytes)

    @staticmethod
    def _craft_raw_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, payload: Any) -> bytes:
        """Crafts minimal Ethernet + IPv4 + TCP/UDP frame bytes."""
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8", errors="ignore")
        else:
            payload_bytes = bytes(payload)

        # 1. Ethernet Header (14 bytes): Dst MAC, Src MAC, EtherType (0x0800 = IPv4)
        eth_hdr = struct.pack(
            "!6s6sH",
            b"\x00\x11\x22\x33\x44\x55",  # Dst MAC
            b"\x66\x77\x88\x99\xaa\xbb",  # Src MAC
            0x0800                        # IPv4
        )

        # 2. IP Header
        ip_proto = 6 if proto.upper() == "TCP" else (17 if proto.upper() == "UDP" else 1)
        src_ip_packed = socket.inet_aton(src_ip)
        dst_ip_packed = socket.inet_aton(dst_ip)

        # Transport Header
        if ip_proto == 6:  # TCP
            # 20 bytes TCP header: src_port, dst_port, seq, ack, offset_flags, window, checksum, urg
            tcp_hdr = struct.pack(
                "!HHIIBBHHH",
                src_port,
                dst_port,
                10001,
                0,
                (5 << 4),  # 5 32-bit words (20 bytes)
                0x02,      # SYN flag
                8192,
                0,         # Checksum 0 for mock
                0
            )
            transport_layer = tcp_hdr + payload_bytes
        elif ip_proto == 17:  # UDP
            udp_len = 8 + len(payload_bytes)
            udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
            transport_layer = udp_hdr + payload_bytes
        else:  # ICMP
            icmp_hdr = struct.pack("!BBHHH", 8, 0, 0, 1, 1)  # Echo Request
            transport_layer = icmp_hdr + payload_bytes

        ip_total_len = 20 + len(transport_layer)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,             # Version 4, IHL 5
            0,                # Type of Service
            ip_total_len,     # Total Length
            54321,            # Identification
            0,                # Flags & Fragment
            64,               # TTL
            ip_proto,         # Protocol
            0,                # Checksum
            src_ip_packed,
            dst_ip_packed
        )

        return eth_hdr + ip_hdr + transport_layer

    @staticmethod
    def parse_pcap_file(filepath: Path) -> List[NetworkFlow]:
        """
        Parses a .pcap file into NetworkFlow records.
        """
        flows = []
        if not filepath.exists():
            return flows

        with open(filepath, "rb") as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return flows

            magic = struct.unpack("=I", global_hdr[:4])[0]
            endian = "<" if magic == 0xd4c3b2a1 else "="

            flow_map: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}

            while True:
                pkt_hdr_bytes = f.read(16)
                if len(pkt_hdr_bytes) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr_bytes)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < 14:
                    continue

                # Ethernet Header
                eth_type = struct.unpack("!H", pkt_data[12:14])[0]
                if eth_type != 0x0800:  # Not IPv4
                    continue

                ip_data = pkt_data[14:]
                if len(ip_data) < 20:
                    continue

                ip_proto = ip_data[9]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])

                ihl = (ip_data[0] & 0x0f) * 4
                trans_data = ip_data[ihl:]

                src_port, dst_port = 0, 0
                payload_str = ""
                proto_name = ProtocolType.OTHER

                if ip_proto == 6 and len(trans_data) >= 20:  # TCP
                    proto_name = ProtocolType.TCP
                    src_port, dst_port = struct.unpack("!HH", trans_data[:4])
                    data_offset = (trans_data[12] >> 4) * 4
                    raw_payload = trans_data[data_offset:]
                    if raw_payload:
                        payload_str = raw_payload[:128].decode("utf-8", errors="ignore")
                elif ip_proto == 17 and len(trans_data) >= 8:  # UDP
                    proto_name = ProtocolType.UDP
                    src_port, dst_port = struct.unpack("!HH", trans_data[:4])
                    raw_payload = trans_data[8:]
                    if raw_payload:
                        payload_str = raw_payload[:128].decode("utf-8", errors="ignore")
                elif ip_proto == 1:
                    proto_name = ProtocolType.ICMP

                key = (src_ip, src_port, dst_ip, dst_port)
                if key not in flow_map:
                    flow_map[key] = {
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": proto_name,
                        "src_bytes": len(pkt_data),
                        "dst_bytes": 0,
                        "src_packets": 1,
                        "dst_packets": 0,
                        "duration": 0.05,
                        "payload": payload_str
                    }
                else:
                    flow_map[key]["src_bytes"] += len(pkt_data)
                    flow_map[key]["src_packets"] += 1
                    flow_map[key]["duration"] += 0.02
                    if payload_str and not flow_map[key]["payload"]:
                        flow_map[key]["payload"] = payload_str

            for item in flow_map.values():
                service = "http" if item["dst_port"] in (80, 8080) else ("https" if item["dst_port"] == 443 else ("ssh" if item["dst_port"] == 22 else "other"))
                flows.append(NetworkFlow(
                    src_ip=item["src_ip"],
                    src_port=item["src_port"],
                    dst_ip=item["dst_ip"],
                    dst_port=item["dst_port"],
                    protocol=item["protocol"],
                    service=service,
                    duration=round(item["duration"], 3),
                    src_bytes=item["src_bytes"],
                    dst_bytes=item["dst_bytes"],
                    src_packets=item["src_packets"],
                    dst_packets=item["dst_packets"],
                    payload_preview=item["payload"] if item["payload"] else None
                ))

        return flows
