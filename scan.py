import socket
import json
import time
import datetime
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys

class NetworkScanner:
    def __init__(self):
        self.scan_time = datetime.datetime.now()
        self.scan_id = int(time.time())
        # Maximum performance settings
        self.sock_timeout = 0.05  # Ultra-aggressive timeout
        self.max_workers = min(8192, os.cpu_count() * 512)  # Maximize threads
        self.batch_size = 4096  # Large batch size for scanning
        self.retries = 0  # No retries for speed
        
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        return local_ip

    def get_network_range(self):
        local_ip = self.get_local_ip()
        return ipaddress.IPv4Network(f"{local_ip}/24", strict=False)

    def scan_port(self, target_ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.sock_timeout)
                if sock.connect_ex((str(target_ip), port)) == 0:
                    return {
                        'ip': str(target_ip),
                        'port': port,
                        'timestamp': datetime.datetime.now().isoformat()
                    }
        except:
            pass
        return None

    def scan_batch(self, batch):
        results = []
        for ip, port in batch:
            result = self.scan_port(ip, port)
            if result:
                results.append(result)
                print(f"OPEN: {ip}:{port}")
        return results

    def scan_network(self, start_port=1, end_port=65535):
        network = self.get_network_range()
        print(f"SCANNING NETWORK: {network}")
        start_time = time.time()
        all_results = []

        # Create all IP:port combinations
        scan_tasks = [
            (ip, port) 
            for ip in network.hosts() 
            for port in range(start_port, end_port + 1)
        ]

        # Split into batches
        batches = [
            scan_tasks[i:i + self.batch_size] 
            for i in range(0, len(scan_tasks), self.batch_size)
        ]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_batch, batch) for batch in batches]
            for future in as_completed(futures):
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                except:
                    continue

        duration = time.time() - start_time
        
        report = {
            'scan_id': self.scan_id,
            'network': str(network),
            'duration': duration,
            'findings': all_results,
            'total_open': len(all_results),
            'ports_scanned': f"{start_port}-{end_port}"
        }

        with open(f"scan_{self.scan_id}.json", 'w') as f:
            json.dump(report, f)

        print(f"\nSCAN COMPLETE: {duration:.2f}s")
        print(f"OPEN PORTS: {len(all_results)}")
        return report

if __name__ == "__main__":
    try:
        scanner = NetworkScanner()
        scanner.scan_network()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
