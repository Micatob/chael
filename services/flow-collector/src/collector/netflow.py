import socket
import struct
import logging
from datetime import datetime, timezone
from models.schema import FlowRecord, FlowDirection
from storage.opensearch_client import OpenSearchClient
from config import settings

logger = logging.getLogger(__name__)

NETFLOW_V5_HEADER_FMT = "!HHIIIIBBH"
NETFLOW_V5_RECORD_FMT = "!IIIHHIIIIHHBBBBHHBB"
NETFLOW_V5_HEADER_SIZE = struct.calcsize(NETFLOW_V5_HEADER_FMT)
NETFLOW_V5_RECORD_SIZE = struct.calcsize(NETFLOW_V5_RECORD_FMT)

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    132: "SCTP",
}

def _ip_to_str(ip_int: int) -> str:
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def _determine_direction(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> FlowDirection:
    private_ranges = [
        ("10.",),
        ("172.16.",),
        ("192.168.",),
        ("127.",),
    ]
    src_private = any(src_ip.startswith(p) for p in private_ranges[0])
    # More robust check
    for prefix_list in private_ranges:
        if src_ip.startswith(prefix_list[0]):
            src_private = True
            break
    else:
        src_private = False

    dst_private = any(dst_ip.startswith(p[0]) for p in private_ranges)

    if src_private and not dst_private:
        return FlowDirection.EGRESS
    elif not src_private and dst_private:
        return FlowDirection.INGRESS
    return FlowDirection.UNKNOWN

class NetFlowCollector:
    def __init__(self, storage: OpenSearchClient):
        self.storage = storage
        self.sock = None
        self.running = False

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", settings.NETFLOW_PORT))
        self.sock.settimeout(1.0)
        logger.info(f"NetFlow v5 collector listening on UDP port {settings.NETFLOW_PORT}")

        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                self._process_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"NetFlow receive error: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
            logger.info("NetFlow collector stopped")

    def _process_packet(self, data: bytes, addr: tuple):
        if len(data) < NETFLOW_V5_HEADER_SIZE:
            return

        header = struct.unpack(NETFLOW_V5_HEADER_FMT, data[:NETFLOW_V5_HEADER_SIZE])
        version, count = header[0], header[1]

        if version != 5:
            logger.warning(f"Unsupported NetFlow version {version} from {addr}")
            return

        unix_secs = header[3]
        sys_uptime = header[2]
        now_ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

        record_start = NETFLOW_V5_HEADER_SIZE
        for i in range(min(count, (len(data) - NETFLOW_V5_HEADER_SIZE) // NETFLOW_V5_RECORD_SIZE)):
            offset = record_start + i * NETFLOW_V5_RECORD_SIZE
            rec_data = data[offset:offset + NETFLOW_V5_RECORD_SIZE]
            if len(rec_data) < NETFLOW_V5_RECORD_SIZE:
                break

            rec = struct.unpack(NETFLOW_V5_RECORD_FMT, rec_data)

            src_ip_int = rec[0]
            dst_ip_int = rec[1]
            dPkts = rec[4]
            dOctets = rec[5]
            first_uptime = rec[6]
            last_uptime = rec[7]
            src_port = rec[8]
            dst_port = rec[9]
            prot = rec[12]

            src_ip = _ip_to_str(src_ip_int)
            dst_ip = _ip_to_str(dst_ip_int)

            # Calculate flow start/end timestamps relative to packet timestamp
            uptime_delta_first = (sys_uptime - first_uptime) / 1000.0 if sys_uptime > first_uptime else 0
            uptime_delta_last = (sys_uptime - last_uptime) / 1000.0 if sys_uptime > last_uptime else 0

            duration = uptime_delta_last - uptime_delta_first if uptime_delta_last > uptime_delta_first else 0

            if duration < 0:
                duration = 0

            protocol_name = PROTOCOL_MAP.get(prot, f"PROTO_{prot}")

            flow = FlowRecord(
                timestamp=now_ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_name,
                bytes=dOctets,
                packets=dPkts,
                duration_seconds=duration,
                direction=_determine_direction(src_ip, dst_ip, src_port, dst_port),
                metadata={
                    "collector_addr": addr[0],
                    "input_if": rec[2],
                    "output_if": rec[3],
                    "tcp_flags": rec[11],
                    "tos": rec[13],
                }
            )

            try:
                self.storage.index_flow(flow)
            except Exception as e:
                logger.error(f"Failed to store flow record: {e}")
