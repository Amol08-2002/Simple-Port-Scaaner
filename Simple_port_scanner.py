import socket
import sys
import threading
from queue import Queue
from datetime import datetime

# --- Configuration ---
DEFAULT_NUM_THREADS = 20
SOCKET_TIMEOUT = 0.5 # Shorter timeout for faster scanning of non-responsive ports
BANNER_TIMEOUT = 1.5 # Slightly longer for banner grabbing

# --- Common Ports and Services ---
COMMON_PORTS_LIST = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 113, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 500, 512, 513, 514, 548, 554, 587, 631, 636,
    902, 989, 990, 992, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1701, 1723, 2000,
    2049, 3000, 3128, 3268, 3269, 3306, 3389, 4500, 5000, 5060, 5061, 5353, 5432, 5631,
    5632, 5666, 5672, 5800, 5900, 5901, 5902, 5903, 6000, 6001, 6379, 6660, 6661, 6662,
    6663, 6664, 6665, 6666, 6667, 6668, 6669, 8000, 8008, 8080, 8081, 8181, 8443, 8888,
    9100, 9200, 9300, 9999, 10000, 27017, 30000, 32768
]

COMMON_SERVICES_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP",
    80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCbind", 113: "Ident", 123: "NTP",
    135: "MS RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMPTRAP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "Microsoft-DS (SMB)", 465: "SMTPS",
    500: "ISAKMP", 512: "exec", 513: "login", 514: "shell/syslog",
    548: "AFP", 554: "RTSP", 587: "SMTP Submission",
    631: "IPP (CUPS)", 636: "LDAPS",
    902: "VMware Auth", 989: "FTPS-Data", 990: "FTPS", 992: "TelnetS", 993: "IMAPS", 995: "POP3S",
    1025: "NFS-ACL / MS RPC", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MS SQL Server", 1434: "MS SQL Monitor", 1521: "Oracle",
    1701: "L2TP", 1723: "PPTP", 2000: "Cisco SCCP", 2049: "NFS",
    3000: "Dev HTTP Alt", 3128: "HTTP Proxy",
    3268: "MS Global Catalog", 3269: "MS Global Catalog S",
    3306: "MySQL", 3389: "RDP", 4500: "IPsec NAT-T",
    5000: "UPnP / Dev HTTP", 5060: "SIP", 5061: "SIPS", 5353: "mDNS",
    5432: "PostgreSQL", 5631: "pcANYWHEREdata", 5632: "pcANYWHEREstat",
    5666: "NRPE", 5672: "AMQP",
    5800: "VNC (HTTP)", 5900: "VNC", 5901: "VNC-1", 5902: "VNC-2", 5903: "VNC-3",
    6000: "X11", 6001: "X11-1", 6379: "Redis",
    6660: "IRC", 6661: "IRC", 6662: "IRC", 6663: "IRC", 6664: "IRC",
    6665: "IRC", 6666: "IRC", 6667: "IRC", 6668: "IRC", 6669: "IRC",
    8000: "HTTP Alt", 8008: "HTTP Alt", 8080: "HTTP Alt/Proxy", 8081: "HTTP Alt",
    8181: "HTTP Alt", 8443: "HTTPS Alt", 8888: "HTTP Alt",
    9100: "JetDirect", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9999: " कई Apps", 10000: "Webmin / NDMP",
    27017: "MongoDB",
    30000: "कई Apps", 32768: "RPC (often dynamic)"
}

# --- Global Variables for Threading ---
print_lock = threading.Lock()
port_queue = Queue()
open_ports_details = [] # To store (port, service, banner)

# --- Core Functions ---
def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        with print_lock:
            print(f"[-] Hostname {hostname} could not be resolved.")
        return None

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True
        return False
    except socket.error:
        return False
    finally:
        if 'sock' in locals():
            sock.close()

def grab_banner(ip, port):
    try:
        sock_banner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_banner.settimeout(BANNER_TIMEOUT)
        sock_banner.connect((ip, port))
        
        # Try sending a generic HTTP HEAD request for web ports
        if port == 80 or port == 8080 or port == 443 or port == 8443: # Simple check
             sock_banner.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        
        banner = sock_banner.recv(1024)
        sock_banner.close()
        # Limit banner length and clean it
        decoded_banner = banner.decode(errors='ignore').strip().replace('\n', ' ').replace('\r', '')
        return decoded_banner[:100] + ('...' if len(decoded_banner) > 100 else '')
    except Exception:
        return "N/A"

# --- Worker Thread Function ---
def worker(target_ip_worker, output_file_handle):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except Exception: # Handles if queue becomes empty between check and get
            continue

        if scan_port(target_ip_worker, port):
            banner = grab_banner(target_ip_worker, port)
            service_name = COMMON_SERVICES_MAP.get(port, "Unknown")
            
            result_str = f"[+] Port {port:<5} ({service_name:<18}) is open   \tBanner: {banner}"
            
            with print_lock:
                print(result_str)
                open_ports_details.append((port, service_name, banner))
                if output_file_handle:
                    try:
                        output_file_handle.write(result_str + "\n")
                    except Exception as e:
                        print(f"[!] Error writing to file for port {port}: {e}")
        
        port_queue.task_done()

# --- Main Scanner Logic ---
def main_scanner():
    global open_ports_details # To clear it for multiple scans if this were a library
    open_ports_details = []

    target_host_input = input("Enter the target IP address or hostname: ")
    target_ip = resolve_hostname(target_host_input)

    if not target_ip:
        return

    print("-" * 60)
    print(f"Scanning Target: {target_ip}")
    start_time = datetime.now()
    print(f"Time started: {start_time}")
    print("-" * 60)

    scan_choice = input("Scan common ports (c) or a specific range (r)? [c/r]: ").lower()
    ports_to_scan_list = []

    if scan_choice == 'r':
        try:
            start_port_str = input("Enter start port (1-65535): ")
            end_port_str = input("Enter end port (1-65535): ")
            start_port = int(start_port_str)
            end_port = int(end_port_str)
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                print("Invalid port range. Ports must be between 1 and 65535, and start port <= end port.")
                return
            ports_to_scan_list = list(range(start_port, end_port + 1))
        except ValueError:
            print("Invalid input for port numbers.")
            return
    else:
        ports_to_scan_list = COMMON_PORTS_LIST
        print(f"Scanning {len(COMMON_PORTS_LIST)} common ports...")

    if not ports_to_scan_list:
        print("No ports selected for scanning.")
        return

    # Populate queue
    for p in ports_to_scan_list:
        port_queue.put(p)

    # File output
    save_to_file = input("Save output to a file? (y/n): ").lower()
    output_file = None
    if save_to_file == 'y':
        filename_suggestion = f"scan_results_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filename = input(f"Enter filename (default: {filename_suggestion}): ") or filename_suggestion
        try:
            output_file = open(filename, 'w')
            output_file.write(f"Scan Results for Target: {target_ip}\n")
            output_file.write(f"Time started: {start_time}\n")
            output_file.write("-" * 60 + "\n")
            print(f"Results will be saved to {filename}")
        except IOError as e:
            print(f"[!] Could not open file {filename} for writing: {e}")
            output_file = None # Ensure it's None if open failed

    # Threading
    try:
        num_threads_str = input(f"Enter number of threads (default: {DEFAULT_NUM_THREADS}): ")
        num_threads = int(num_threads_str) if num_threads_str.isdigit() else DEFAULT_NUM_THREADS
        if num_threads <= 0: num_threads = DEFAULT_NUM_THREADS
    except ValueError:
        num_threads = DEFAULT_NUM_THREADS
    
    print(f"Starting scan with {num_threads} threads for {port_queue.qsize()} ports...")

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip, output_file), daemon=True)
        threads.append(thread)
        thread.start()

    # Wait for all ports in the queue to be processed
    port_queue.join()
    
    # Ensure all threads have finished their current task if any (join() on queue is usually enough)
    # for t in threads:
    #    t.join() # This might be redundant if daemon=True and queue.join() works as expected

    end_time = datetime.now()
    total_time = end_time - start_time

    print("\n" + "-" * 60)
    print("Scan Complete.")
    if open_ports_details:
        print(f"Found {len(open_ports_details)} open port(s):")
        # open_ports_details is already printed as found, this is just a summary count.
        # Could re-print sorted here if needed.
    else:
        print("No open ports found.")
    
    print(f"Time finished: {end_time}")
    print(f"Total scan duration: {total_time}")
    print("-" * 60)

    if output_file:
        output_file.write("-" * 60 + "\n")
        output_file.write(f"Scan Complete. Found {len(open_ports_details)} open port(s).\n")
        output_file.write(f"Time finished: {end_time}\n")
        output_file.write(f"Total scan duration: {total_time}\n")
        output_file.close()
        print(f"Results saved to {filename}")

if __name__ == "__main__":
    try:
        main_scanner()
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        # Attempt to clean up resources if needed, though daemon threads will exit
        if 'output_file' in locals() and output_file and not output_file.closed:
            output_file.write("\n[!] Scan aborted by user.\n")
            output_file.close()
            print("Partial results may have been saved.")
        sys.exit()
    except Exception as e:
        print(f"\n[!] An unexpected error occurred in main: {e}")
        import traceback
        traceback.print_exc()