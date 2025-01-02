#!/usr/bin/env python3

import socket
import json
import time
import random
import datetime
import ipaddress
import sys
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

########################
# Configure Logging
########################
logger = logging.getLogger("ExtremeScanner")
logger.setLevel(logging.DEBUG)  # Log everything at DEBUG or above

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

@dataclass
class ScannerConfig:
    """
    Configuration for high-speed TCP scanning and custom messages.
    """
    sock_timeout: float = 0.01
    max_workers: int = field(default=None)   # None -> auto-calc
    batch_size: int = 8192
    retries: int = 0
    start_port: int = 1
    end_port: int = 65535
    wait_for_reply: bool = True             # If True, read a small response
    # For advanced features: a dictionary mapping port -> payload (bytes)
    port_payloads: dict = field(default_factory=dict)
    default_payload: bytes = b"HELLO SERVER"

def generate_random_subnets(num_subnets=10, prefix=24):
    """
    Generates random IPv4 subnets (e.g., /24).
    Skips private/reserved ranges; returns list like ['8.8.8.0/24', ...].
    """
    logger.info("Generating random subnets...")
    private_ranges = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("100.64.0.0/10")
    ]

    def is_private_or_reserved(ip_net):
        return any(ip_net.subnet_of(r) for r in private_ranges)

    subnets = []
    while len(subnets) < num_subnets:
        octets = [random.randint(1, 254) for _ in range(4)]
        cidr_str = f"{'.'.join(map(str, octets))}/{prefix}"
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if not is_private_or_reserved(net):
                subnets.append(str(net))
        except:
            pass
    logger.info(f"Generated {len(subnets)} random public subnets.")
    return subnets

class ExtremeScanner:
    """
    Ultra-aggressive TCP scanner:
      - Very short timeouts
      - Multiple port payloads
      - Minimal banner parsing for known protocols
      - High concurrency (up to 16,384 threads)
      - Discovers new subnets from scanned banners
    """
    def __init__(self, config: ScannerConfig):
        self.cfg = config
        self.scan_id = int(time.time())
        if self.cfg.max_workers is None:
            # auto-calc: up to 16k or CPU_cores*1024
            self.cfg.max_workers = min(16384, (os.cpu_count() or 1)*1024)

        # Track newly discovered subnets and total attempts
        self.new_subnets = set()
        self.total_attempts = 0

        logger.info("ExtremeScanner initialized (TCP only) with:")
        logger.info(f" - sock_timeout={self.cfg.sock_timeout}")
        logger.info(f" - max_workers={self.cfg.max_workers}")
        logger.info(f" - batch_size={self.cfg.batch_size}")
        logger.info(f" - retries={self.cfg.retries}")
        logger.info(f" - port_range={self.cfg.start_port}-{self.cfg.end_port}")
        logger.info(f" - wait_for_reply={self.cfg.wait_for_reply}")

    def scan_port(self, ip_str, port):
        """
        Attempt a TCP connect; increment total_attempts.
        """
        self.total_attempts += 1
        for _ in range(self.cfg.retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.cfg.sock_timeout)
                    if sock.connect_ex((ip_str, port)) == 0:
                        # Port is open
                        logger.debug(f"OPEN (TCP): {ip_str}:{port}")
                        self._handle_tcp_open(sock, ip_str, port)
                        return {
                            "ip": ip_str,
                            "port": port,
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                            "protocol": "TCP"
                        }
            except Exception as ex:
                logger.debug(f"TCP error {ip_str}:{port} -> {ex}")
        return None

    def _handle_tcp_open(self, sock, ip_str, port):
        """
        Send port-specific or default payload, optionally parse response.
        Then do minimal banner checks for port 80/443 if not already covered.
        """
        # 1) Determine payload
        payload = self.cfg.port_payloads.get(port, self.cfg.default_payload)

        # 2) Send payload
        if payload:
            try:
                sock.sendall(payload)
                if self.cfg.wait_for_reply:
                    sock.settimeout(0.2)
                    reply = sock.recv(4096)
                    logger.debug(f"REPLY from {ip_str}:{port}: {reply[:100]!r}")
                    # Try to detect a known protocol
                    self._try_protocol_detection(reply, port)
                    # Parse for new subnets
                    self._parse_banner_for_subnets(reply.decode(errors='ignore'))
            except:
                pass

        # 3) Additional minimal HTTP banner check for 80/443
        #    in case not specifically handled in port_payloads
        if port in (80, 443):
            try:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
                sock.settimeout(0.2)
                resp = sock.recv(4096).decode(errors='ignore')
                self._parse_banner_for_subnets(resp)
            except:
                pass

    def _try_protocol_detection(self, data, port):
        """
        Basic detection for SSH, HTTP, SMTP, etc.
        """
        snippet = data[:50].decode(errors='ignore').strip()
        if snippet.startswith("SSH-"):
            logger.debug(f"Protocol detection: SSH on port {port}")
        elif "HTTP" in snippet or "Server:" in snippet:
            logger.debug(f"Protocol detection: HTTP on port {port}")
        elif snippet.startswith("220") or "SMTP" in snippet:
            logger.debug(f"Protocol detection: SMTP on port {port}")
        # Add more if needed (FTP, POP3, IMAP)...

    def _parse_banner_for_subnets(self, text):
        """
        Look for IP-like strings, form /24, add to new_subnets if public.
        """
        tokens = text.split()
        for t in tokens:
            parts = t.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                ip_candidate = ".".join(parts)
                try:
                    net_candidate = ipaddress.ip_network(ip_candidate + "/24", strict=False)
                    if (net_candidate.num_addresses > 1
                            and not net_candidate.is_private
                            and not net_candidate.is_reserved):
                        logger.info(f"Discovered new subnet: {net_candidate}")
                        self.new_subnets.add(str(net_candidate))
                except:
                    pass

    def scan_batch(self, batch):
        """
        Scan a list of (ip_str, port) tasks sequentially.
        """
        results = []
        for ip_str, port in batch:
            out = self.scan_port(ip_str, port)
            if out:
                results.append(out)
        return results

    def scan_subnet(self, subnet):
        """
        Build (ip, port) combos for hosts in a subnet, then scan in batches.
        """
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = list(net.hosts())
        logger.info(f"\n[SUBNET SCAN START] {subnet}")
        logger.info(f"Hosts: {len(hosts)} | Ports: {self.cfg.start_port}-{self.cfg.end_port}")

        start_time = time.time()

        tasks = [
            (str(ip), port)
            for ip in hosts
            for port in range(self.cfg.start_port, self.cfg.end_port+1)
        ]

        # chunk into batches
        batches = [
            tasks[i:i + self.cfg.batch_size]
            for i in range(0, len(tasks), self.cfg.batch_size)
        ]

        all_open = []
        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as exe:
            future_list = [exe.submit(self.scan_batch, b) for b in batches]
            for fut in as_completed(future_list):
                results = fut.result()
                if results:
                    all_open.extend(results)

        elapsed = time.time() - start_time
        logger.info(f"[SUBNET SCAN DONE] {subnet} -> {len(all_open)} open ports in {elapsed:.2f}s\n")
        return all_open

    def scan_subnets(self, subnets):
        """
        Scan multiple subnets, returning a consolidated list of open ports.
        """
        grand_results = []
        for snet in subnets:
            grand_results.extend(self.scan_subnet(snet))
            logger.info(f"TRAFFIC STATS: {self.total_attempts} attempts so far.")
        return grand_results

    def run_recursive_scans(self, initial_subnets, sleep_time=60):
        """
        Repeatedly scan subnets, discover new ones from banners, log results.
        """
        scanned_subnets = set(initial_subnets)
        logger.info(f"Initial subnets: {scanned_subnets}")

        while True:
            # Merge newly discovered subnets
            new_unscanned = self.new_subnets - scanned_subnets
            if new_unscanned:
                logger.info(f"Found {len(new_unscanned)} newly discovered subnets.")
                scanned_subnets.update(new_unscanned)

            if not scanned_subnets:
                logger.warning("No subnets to scan; sleeping...")
                time.sleep(sleep_time)
                continue

            to_scan = list(scanned_subnets)
            logger.info(f"\n=== SCAN ROUND START: {len(to_scan)} subnets ===")
            self.scan_id = int(time.time())
            found_open = self.scan_subnets(to_scan)

            # Save JSON report
            out_data = {
                "scan_id": self.scan_id,
                "time": datetime.datetime.utcnow().isoformat(),
                "subnets_scanned": to_scan,
                "results_count": len(found_open),
                "results": found_open,
                "discovered_subnets": list(self.new_subnets),
                "total_connection_attempts": self.total_attempts
            }
            stamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"extreme_scan_{self.scan_id}_{stamp}.json"
            with open(filename, "w") as fp:
                json.dump(out_data, fp, indent=2)

            logger.info(f"Scan round complete. Found {len(found_open)} open ports total.")
            logger.info(f"Saved results to {filename}")
            logger.info(f"TRAFFIC STATS: {self.total_attempts} total attempts.")
            logger.info(f"Sleeping {sleep_time}s...\n")
            time.sleep(sleep_time)

def main():
    # 1) Example port-specific messages: SSH, SMTP, HTTP, etc.
    sample_port_payloads = {
        22: b"SSH-2.0-MyScanner\r\n",                # For SSH
        25: b"HELO example.com\r\n",                 # For SMTP
        80: b"GET / HTTP/1.1\r\nHost: test\r\n\r\n", # For HTTP
        443: b"",                                    # For HTTPS (no payload, or use TLS handshake logic)
        110: b"USER test\r\n",                       # POP3
        143: b"A1 CAPABILITY\r\n"                    # IMAP
    }

    # 2) Build a config for maximum aggressiveness
    cfg = ScannerConfig(
        sock_timeout=0.005,     # super short
        max_workers=None,       # auto-calc for huge concurrency
        batch_size=8192,        # large batches
        retries=0,              # no retries
        start_port=1,
        end_port=1024,          # can set to 65535 for total coverage
        wait_for_reply=True,
        port_payloads=sample_port_payloads,
        default_payload=b"HELLO SERVER"
    )

    # 3) Generate random subnets or define your own
    random_subs = generate_random_subnets(num_subnets=3, prefix=24)
    known_subs = ["8.8.8.0/24"]
    initial_subnets = set(random_subs + known_subs)

    # 4) Create the scanner
    scanner = ExtremeScanner(cfg)

    # 5) Start infinite scanning
    try:
        scanner.run_recursive_scans(initial_subnets, sleep_time=30)
    except KeyboardInterrupt:
        logger.info("Scanner interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
