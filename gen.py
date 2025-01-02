import random
import ipaddress

def generate_random_subnets(num_subnets=5, prefix=29):
    """
    Generates random IPv4 CIDR blocks (e.g., /29 subnets).
    Skips private/reserved ranges.
    Returns a list of string subnets like '123.45.67.0/29'.
    """
    subnets = []
    # Common private/reserved networks to skip:
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

    def is_private_or_reserved(ip):
        return any(ip.subnet_of(r) for r in private_ranges)

    while len(subnets) < num_subnets:
        # Generate random IP
        octets = [random.randint(1, 254) for _ in range(4)]
        ip_str = ".".join(map(str, octets))
        try:
            network = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
            # Skip if network is private/reserved
            if not is_private_or_reserved(network):
                subnets.append(str(network))
        except:
            pass
    return subnets

# Example usage
if __name__ == "__main__":
    random_subnets = generate_random_subnets(num_subnets=10, prefix=29)
    print("Generated Random Subnets:")
    for sn in random_subnets:
        print(sn)
