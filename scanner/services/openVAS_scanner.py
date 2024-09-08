# scanner/services/nmap_scanner.py
import nmap

def scan_ip(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '3000')
    services = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = {
                    'ip_address': host,
                    'port': port,
                    'name': nm[host][proto][port]['name'],
                    'version': nm[host][proto][port]['version']
                }
                services.append(service)
    return services
