import concurrent.futures
import ipaddress
from icmplib import ping

# Try relative import first, fallback to absolute or direct module import
try:
    from .utils import parse_subnet
except ImportError:
    try:
        from scanner.utils import parse_subnet
    except ImportError:
        from utils import parse_subnet

def ping_host(ip, timeout=1):
    """
    Pings a single IP address using icmplib.
    
    Args:
        ip (str): The IP address to ping.
        timeout (float): Timeout for the ping in seconds. Default is 1.
        
    Returns:
        dict: A dictionary containing 'ip', 'alive' (bool), and 'latency' (float or None).
    """
    try:
        # Note: icmplib's default `privileged=True` requires root/administrator privileges.
        # If running as standard user, you might need to add `privileged=False` here and configure OS.
        host = ping(str(ip), count=1, timeout=timeout)
        return {
            "ip": str(ip),
            "alive": host.is_alive,
            "latency": host.avg_rtt if host.is_alive else None
        }
    except Exception:
        # Catch errors such as SocketPermissionError and return as dead
        return {
            "ip": str(ip),
            "alive": False,
            "latency": None
        }

def scan_subnet(subnet, timeout=1, max_workers=100):
    """
    Pings all hosts in a subnet concurrently to discover live hosts.
    
    Args:
        subnet (str): The CIDR string representation of the subnet (e.g., '192.168.1.0/24').
        timeout (float): Timeout per ping in seconds. Default is 1.
        max_workers (int): Maximum number of threads to use. Default is 100.
        
    Returns:
        list: A sorted list of dicts representing the alive hosts.
    """
    ips = parse_subnet(subnet)
    alive_hosts = []
    
    # Use ThreadPoolExecutor to run tasks concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, ip, timeout): ip for ip in ips}
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.get("alive"):
                # Print live host details as they are discovered
                print(f"[+] Host {result['ip']:<15} is alive (Latency: {result['latency']} ms)")
                alive_hosts.append(result)
                
    # Sort hosts numerically by IP address instead of lexicographically
    alive_hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    
    return alive_hosts
