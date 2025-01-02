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

########################
# Configure Logging
########################
logger = logging.getLogger("ExtremeScanner")
logger.setLevel(logging.DEBUG)  # Log everything DEBUG and above

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)

# Format: [TIME] [LEVEL] MESSAGE
formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

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

    def is_private_or_reserved(net):
        return any(net.subnet_of(r) for r in private_ranges)

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
    Ultra-aggressive scanner with:
      - Very short socket timeouts
      - High concurrency
      - Potentially scans all ports (1-65535)
      - Recursively discovers new subnets from minimal HTTP banners
      - Tracks total connection attempts in console
    """
    def __init__(self,
                 sock_timeout=0.01,
                 max_workers=None,
                 batch_size=8192,
                 retries=0,
                 start_port=1,
                 end_port=65535):
        self.scan_id = int(time.time())
        self.sock_timeout = sock_timeout
        self.max_workers = max_workers or min(16384, (os.cpu_count() or 1)*1024)
        self.batch_size = batch_size
        self.retries = retries
        self.start_port = start_port
        self.end_port = end_port
        self.new_subnets = set()  # newly discovered subnets for recursive scanning

        # Track total connection attempts (printed in console)
        self.total_attempts = 0

        logger.info("ExtremeScanner initialized with:")
        logger.info(f" - sock_timeout={self.sock_timeout}")
        logger.info(f" - max_workers={self.max_workers}")
        logger.info(f" - batch_size={self.batch_size}")
        logger.info(f" - retries={self.retries}")
        logger.info(f" - port_range={self.start_port}-{self.end_port}")

    def scan_port(self, ip_str, port):
        """
        Attempt a TCP connect to ip_str:port, logging progress.
        Increments total_attempts every time we try a connection.
        """
        for _ in range(self.retries + 1):
            # Count every connection attempt
            self.total_attempts += 1

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.sock_timeout)
                    if sock.connect_ex((ip_str, port)) == 0:
                        logger.debug(f"OPEN: {ip_str}:{port}")
                        # Minimal banner check if port is 80 or 443
                        if port in (80, 443):
                            try:
                                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                                sock.settimeout(0.1)
                                resp = sock.recv(2048).decode(errors='ignore')
                                self._parse_banner_for_subnets(resp)
                            except:
                                pass
                        return {
                            "ip": ip_str,
                            "port": port,
                            "timestamp": datetime.datetime.utcnow().isoformat()
                        }
            except Exception as ex:
                logger.debug(f"Error connecting {ip_str}:{port} -> {ex}")
        return None

    def _parse_banner_for_subnets(self, banner_text):
        """
        Detect strings that look like IPs, form a /24,
        then store them for future scanning. 
        """
        tokens = banner_text.split()
        for t in tokens:
            parts = t.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                ip_candidate = ".".join(parts)
                try:
                    net_candidate = ipaddress.ip_network(ip_candidate + "/24", strict=False)
                    if net_candidate.num_addresses > 1 and not (net_candidate.is_private or net_candidate.is_reserved):
                        logger.info(f"Discovered possible new subnet: {net_candidate}")
                        self.new_subnets.add(str(net_candidate))
                except:
                    pass

    def scan_batch(self, batch):
        """
        Scan a batch of (ip_str, port) tasks sequentially.
        """
        results = []
        for ip_str, port in batch:
            res = self.scan_port(ip_str, port)
            if res:
                results.append(res)
        return results

    def scan_subnet(self, subnet):
        """
        Generate (ip, port) combos for all hosts in a subnet.
        """
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = list(net.hosts())
        logger.info(f"\n[SUBNET SCAN START] {subnet}")
        logger.info(f"Hosts: {len(hosts)} | Ports: {self.start_port}-{self.end_port}")

        start_t = time.time()
        tasks = [(str(ip), p)
                 for ip in hosts
                 for p in range(self.start_port, self.end_port+1)]
        
        # Break into batches
        batches = [tasks[i:i+self.batch_size]
                   for i in range(0, len(tasks), self.batch_size)]

        open_results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as exe:
            future_list = [exe.submit(self.scan_batch, b) for b in batches]
            for fut in as_completed(future_list):
                chunk = fut.result()
                if chunk:
                    open_results.extend(chunk)

        elapsed = time.time() - start_t
        logger.info(f"[SUBNET SCAN DONE] {subnet} -> {len(open_results)} open ports in {elapsed:.2f}s\n")
        return open_results

    def scan_subnets(self, subnets):
        """
        Scan multiple subnets, consolidate results.
        """
        all_open = []
        for snet in subnets:
            all_open.extend(self.scan_subnet(snet))
            # Print ongoing traffic info after each subnet
            logger.info(f"TRAFFIC STATS: {self.total_attempts} connection attempts so far.")
        return all_open

    def run_recursive_scans(self, initial_subnets, sleep_time=60):
        """
        Keep scanning existing and newly discovered subnets in a loop.
        Save JSON after each iteration. Sleep between scans.
        """
        scanned_subnets = set(initial_subnets)
        logger.info(f"Initial subnets: {scanned_subnets}")

        while True:
            # Merge newly discovered subnets we haven't scanned yet
            new_unscanned = self.new_subnets - scanned_subnets
            if new_unscanned:
                logger.info(f"Found {len(new_unscanned)} newly discovered subnets to scan.")
                scanned_subnets.update(new_unscanned)

            # If no subnets, just wait
            if not scanned_subnets:
                logger.warning("No subnets to scan; sleeping...")
                time.sleep(sleep_time)
                continue

            subnets_to_scan = list(scanned_subnets)
            logger.info(f"\n=== SCAN ROUND START: {len(subnets_to_scan)} subnets ===")
            self.scan_id = int(time.time())  # update ID each round
            found_open = self.scan_subnets(subnets_to_scan)

            # Save scan results
            out_report = {
                "scan_id": self.scan_id,
                "time": datetime.datetime.utcnow().isoformat(),
                "subnets_scanned": subnets_to_scan,
                "results_count": len(found_open),
                "results": found_open,
                "discovered_subnets": list(self.new_subnets),
                "total_connection_attempts": self.total_attempts
            }
            stamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out_file = f"extreme_scan_{self.scan_id}_{stamp}.json"
            with open(out_file, "w") as fp:
                json.dump(out_report, fp, indent=2)

            logger.info(f"Scan round complete. Found {len(found_open)} open ports total.")
            logger.info(f"Saved results to {out_file}")
            logger.info(f"TRAFFIC STATS: {self.total_attempts} total connection attempts thus far.")
            logger.info(f"Sleeping {sleep_time}s before next round...\n")
            time.sleep(sleep_time)

def main():
    # Generate random subnets
    random_subs = generate_random_subnets(num_subnets=3, prefix=24)
    # You could also add known subnets here if desired
    known_subs = ["8.8.8.0/24"]
    initial = set(random_subs + known_subs)

    # Create scanner with extreme concurrency
    scanner = ExtremeScanner(
        sock_timeout=0.01,
        max_workers=None,  # auto-calc
        batch_size=8192,
        retries=0,
        start_port=1,
        end_port=65535
    )

    # Start infinite recursion scanning
    try:
        scanner.run_recursive_scans(initial, sleep_time=60)
    except KeyboardInterrupt:
        logger.info("Scanner interrupted by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
