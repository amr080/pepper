#!/usr/bin/env python3

import socket
import json
import time
import random
import datetime
import ipaddress
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def generate_random_subnets(num_subnets=10, prefix=29):
    """
    Generate random IPv4 CIDR blocks (e.g., /29).
    Skips private/reserved ranges. Returns list like ['8.8.8.0/29', ...].
    """
    private_ranges = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),   # Multicast
        ipaddress.ip_network("240.0.0.0/4"),   # Reserved
        ipaddress.ip_network("100.64.0.0/10")  # Carrier-grade NAT
    ]
    def is_private_or_reserved(net):
        return any(net.subnet_of(r) for r in private_ranges)

    subnets = []
    while len(subnets) < num_subnets:
        octets = [random.randint(1, 254) for _ in range(4)]
        cidr = f"{'.'.join(map(str, octets))}/{prefix}"
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if not is_private_or_reserved(net):
                subnets.append(str(net))
        except:
            pass
    return subnets

class ScaleScanner:
    """
    Aggressive scanner with:
      - very short socket timeouts
      - high concurrency
      - optional large port ranges
      - repeated scanning
    """
    def __init__(self, sock_timeout=0.05, max_workers=None, batch_size=4096, retries=0):
        self.scan_id = int(time.time())
        self.sock_timeout = sock_timeout
        # If not set, pick a large number limited by CPU cores
        self.max_workers = max_workers or min(8192, (os.cpu_count() or 1) * 512)
        self.batch_size = batch_size
        self.retries = retries

    def scan_port(self, ip_str, port):
        """Try connecting to ip_str:port. Return dict if open, else None."""
        for _ in range(self.retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.sock_timeout)
                    if sock.connect_ex((ip_str, port)) == 0:
                        print(f"OPEN: {ip_str}:{port}")
                        return {
                            "ip": ip_str,
                            "port": port,
                            "timestamp": datetime.datetime.utcnow().isoformat()
                        }
            except:
                pass
        return None

    def scan_batch(self, batch):
        """Scan a batch of (ip_str, port) tuples."""
        results = []
        for ip_str, port in batch:
            out = self.scan_port(ip_str, port)
            if out:
                results.append(out)
        return results

    def scan_subnet(self, subnet, start_port=1, end_port=1024):
        """
        Breaks a subnet's IP:port combos into batches
        and scans in a ThreadPool for concurrency.
        """
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = list(net.hosts())
        print(f"\n=== SCANNING SUBNET: {subnet}, "
              f"Ports {start_port}-{end_port}, {len(hosts)} possible hosts ===")

        # Create IP:port tasks
        tasks = [(str(ip), port)
                 for ip in hosts
                 for port in range(start_port, end_port+1)]

        # Divide tasks into batches
        batches = [tasks[i:i + self.batch_size]
                   for i in range(0, len(tasks), self.batch_size)]

        all_open = []
        start_t = time.time()
        with ThreadPoolExecutor(max_workers=self.max_workers) as exe:
            future_list = [exe.submit(self.scan_batch, b) for b in batches]
            for fut in as_completed(future_list):
                batch_result = fut.result()
                if batch_result:
                    all_open.extend(batch_result)
        elapsed = time.time() - start_t

        print(f"Subnet {subnet} scan done in {elapsed:.2f}s, open ports found: {len(all_open)}")
        return all_open

    def scan_subnets(self, subnets, start_port=1, end_port=1024):
        """Scan multiple subnets sequentially, return all results."""
        grand_results = []
        for snet in subnets:
            results = self.scan_subnet(snet, start_port, end_port)
            grand_results.extend(results)

        # Save once after scanning all subnets
        out_report = {
            "scan_id": self.scan_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "subnets_scanned": subnets,
            "port_range": f"{start_port}-{end_port}",
            "open_ports": grand_results,
            "total_open": len(grand_results)
        }
        out_file = f"scale_scan_{self.scan_id}.json"
        with open(out_file, "w") as f:
            json.dump(out_report, f, indent=2)
        print(f"\n[SCAN COMPLETE]: {len(grand_results)} open ports total")
        print(f"Results saved to {out_file}")
        return out_report

def main():
    # Example: generate 10 random subnets (/29), plus some known subnets
    random_subnets = generate_random_subnets(num_subnets=10, prefix=29)
    known_subnets = ["8.8.8.0/29", "8.8.4.0/29"]

    # Merge them
    subnets = known_subnets + random_subnets

    # Create a scanner with ultra-aggressive settings
    scanner = ScaleScanner(sock_timeout=0.05, max_workers=2000, batch_size=4096, retries=0)

    try:
        # Continuously re-scan in a loop
        while True:
            scanner.scan_subnets(subnets, start_port=1, end_port=1024)
            print("Sleeping 60s before next cycle...")
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nExiting scan loop. Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()
