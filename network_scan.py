import scapy.all as scapy
import socket
import threading
from queue import Queue
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import nmap3

def scan(ip, result_queue):
    try:
        arp_request = scapy.ARP(pdst=ip)  # type: ignore
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # type: ignore
        packet = broadcast/arp_request
        answer = scapy.srp(packet, timeout=1, verbose=False)[0]

        clients = []
        for client in answer:
            client_info = {'IP': client[1].psrc, 'MAC': client[1].hwsrc}
            try:
                hostname = socket.gethostbyaddr(client_info['IP'])[0]
                client_info['Hostname'] = hostname
            except socket.herror:
                client_info['Hostname'] = 'Unknown'
            clients.append(client_info)
        result_queue.put(clients)
    except Exception as e:
        print(f"Error scanning {ip}: {e}")

def print_result(result):
    print('IP' + " "*20 + 'MAC' + " "*20 + 'Hostname')
    print('-'*80)
    for client in result:
        print(client['IP'] + '\t\t' + client['MAC'] + '\t\t' + client['Hostname'])

def scan_top_ports(hosts, top_n=100):
    nm = nmap3.NmapScanTechniques()
    host_ports = {}

    for host in hosts:
        ip = host['IP']
        result = nm.nmap_tcp_scan(ip, args=f"--top-ports {top_n} -T4")
        ports = []
        for port_data in result.get(ip, {}).get('ports', []):
            if port_data.get('state') == 'open':
                ports.append({
                    'port': port_data['portid'],
                    'protocol': port_data['protocol']
                })
        host_ports[ip] = ports

    return host_ports
#Services & version Detection

def detect_services(ip, ports):
    nm = nmap3.Nmap()
    port_range = ','.join(map(str, ports))

    result = nm.nmap_version_detection(ip, args=f"--version-all -p {port_range}")
    services = []
    for service in result:
        services.append({
            'port': service['port'],
            'service': service['service'].get('name', 'unknown'),
            'version': service['service'].get('version', 'unknown'),
            'product': service['service'].get('product', 'unknown'),
            'banner': f"{service['service'].get('product', '')} {service['service'].get('version', '')}".strip()
        })
    
    return services

def main(cidr):
    results_queue = Queue()
    threads = []
    network = ipaddress.ip_network(cidr, strict=False)

    for ip in network.hosts():
        thread = threading.Thread(target=scan, args=(str(ip), results_queue))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
    
    all_clients = []
    while not results_queue.empty():
        all_clients.extend(results_queue.get())
    
    print_result(all_clients)

    print("Scanning top ports...")
    open_ports = scan_top_ports(all_clients, top_n=100)
    print("\nOpen Ports:")
    for ip, ports in open_ports.items():
        if ports:
            print(f"\nHost: {ip}")
            for p in ports:
                print(f"  Port {p['port']}/{p['protocol']} OPEN")
            print("-" * 50)
            port_numbers = [p['port'] for p in ports]
            services = detect_services(ip, port_numbers)
            print("  Detected Services:")
            for service in services:
                print(f"    Port {service['port']}: {service['service']} - {service['version']} ({service['product']})")
                print(f"    Banner: {service['banner']}")
                print("=" * 50)
if __name__ == '__main__':
    cidr = input("Enter network ip address: ")
    main(cidr)