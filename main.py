import sys

# Attempt to load Colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class MockColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = MockColor()

from scanner.utils import validate_cidr
from scanner.host_discovery import scan_subnet

def display_table(hosts):
    """
    Displays the list of hosts in a clean formatting table.
    """
    column_ip, column_status, column_latency = "IP Address", "Status", "Latency (ms)"
    
    # Table Header
    print("+" + "-"*17 + "+" + "-"*12 + "+" + "-"*15 + "+")
    print(f"| {column_ip:<15} | {column_status:<10} | {column_latency:<13} |")
    print("+" + "-"*17 + "+" + "-"*12 + "+" + "-"*15 + "+")
    
    if not hosts:
        # Handle the case where no hosts were returned
        message = "No alive hosts found".ljust(48)
        print(f"| {Fore.YELLOW}{message}{Style.RESET_ALL} |")
        print("+" + "-"*17 + "+" + "-"*12 + "+" + "-"*15 + "+")
        return
        
    for host in hosts:
        ip = host.get("ip", "Unknown")
        alive = host.get("alive", False)
        latency = host.get("latency")
        
        # Determine the status and apply corresponding coloring
        status_text = "Up" if alive else "Down"
        status_color = Fore.GREEN if alive else Fore.RED
        
        # Format the latency
        latency_str = f"{latency:.2f}" if latency is not None else "N/A"
        
        # Applying padding
        ip_padded = ip.ljust(15)
        status_padded = status_text.ljust(10)
        latency_padded = latency_str.ljust(13)
        
        print(f"| {ip_padded} | {status_color}{status_padded}{Style.RESET_ALL} | {latency_padded} |")
        
    print("+" + "-"*17 + "+" + "-"*12 + "+" + "-"*15 + "+")

def main():
    print(f"{Fore.CYAN}=========================================={Style.RESET_ALL}")
    print(f"{Fore.CYAN}       SMART NETWORK MAPPER SCANNER       {Style.RESET_ALL}")
    print(f"{Fore.CYAN}=========================================={Style.RESET_ALL}")
    
    while True:
        subnet = input("\nEnter the target subnet in CIDR format (e.g., 192.168.1.0/24): ").strip()
        
        if validate_cidr(subnet):
            break
        else:
            print(f"{Fore.RED}[!] Invalid CIDR format. Please provide a valid subnet.{Style.RESET_ALL}")
            
    print(f"\n{Fore.BLUE}[*] Scanning subnet: {subnet} ...{Style.RESET_ALL}\n")
    
    try:
        hosts = scan_subnet(subnet, timeout=1, max_workers=100)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred during the scan: {e}{Style.RESET_ALL}")
        sys.exit(1)
        
    print(f"\n{Fore.BLUE}[*] Scan Complete.{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Displaying Summary Data:{Style.RESET_ALL}\n")
    display_table(hosts)

if __name__ == "__main__":
    main()
