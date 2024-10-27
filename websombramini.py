import requests
import socket
import ssl
import dns.resolver
import json
import whois
import time
import threading
import re
import nmap
import pandas as pd
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
import logging
import sublist3r 
import argparse
import pyfiglet  


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WebSombramini:
    def __init__(self, domain):
        self.domain = domain
        self.url = f"http://{domain}"
        self.data = {
            'Domain': domain,
            'Analysis Timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'IP Address': None,
            'DNS Records': None,
            'SSL Certificate': None,
            'Title': None,
            'Description': None,
            'H1 Tags': None,
            'WHOIS Info': None,
            'Page Size': None,
            'Status Code': None,
            'Links': None,
            'Emails Found': None,
            'Security Headers': None,
            'Subdomains': None,
            'Open Ports': None
        }

    # Banner for the tool
    @staticmethod
    def display_banner():
        banner = pyfiglet.figlet_format("WebSombraMini")
        print(banner)
        print("Web Analysis and Recon Tool\n")
        print("Developed by [root0emir]")
        print("=" * 50)

    # Method to resolve IP address
    def get_ip_address(self):
        try:
            ip_address = socket.gethostbyname(self.domain)
            self.data['IP Address'] = ip_address
            logging.info(f"[+] IP Address: {ip_address}")
        except socket.gaierror:
            logging.error("[-] Unable to get IP address.")
            self.data['IP Address'] = None

    # Method to retrieve DNS records
    def get_dns_records(self):
        try:
            dns_data = {}
            for record_type in ['A', 'MX', 'NS', 'TXT']:
                answers = dns.resolver.resolve(self.domain, record_type)
                dns_data[record_type] = [str(answer) for answer in answers]
                logging.info(f"[+] DNS Records ({record_type}): {dns_data[record_type]}")
            self.data['DNS Records'] = dns_data
        except Exception as e:
            logging.error(f"[-] Error fetching DNS records: {e}")
            self.data['DNS Records'] = None

    # Enhanced SSL Certificate Information
    def get_ssl_info_detailed(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.data['SSL Certificate'] = {
                        'Subject': dict(x[0] for x in cert['subject']),
                        'Issuer': dict(x[0] for x in cert['issuer']),
                        'Valid From': cert['notBefore'],
                        'Valid To': cert['notAfter']
                    }
            logging.info("[+] Detailed SSL Certificate info retrieved.")
        except Exception as e:
            logging.error(f"[-] Error fetching SSL certificate: {e}")
            self.data['SSL Certificate'] = None

    # Website scraping
    def scrape_website(self):
        try:
            response = requests.get(self.url, timeout=10)
            self.data['Status Code'] = response.status_code
            self.data['Page Size'] = len(response.content)

            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                self.data['Title'] = soup.title.string if soup.title else 'No title found'
                description = soup.find("meta", attrs={"name": "description"})
                h1_tags = soup.find_all('h1')
                links = [a['href'] for a in soup.find_all('a', href=True)]
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text)

                self.data['Description'] = description['content'] if description else 'No description found'
                self.data['H1 Tags'] = [h1.get_text() for h1 in h1_tags]
                self.data['Links'] = links
                self.data['Emails Found'] = list(set(emails))
                logging.info(f"[+] Title: {self.data['Title']}")
            else:
                logging.warning(f"[-] Failed to retrieve webpage, status code: {response.status_code}")
        except Exception as e:
            logging.error(f"[-] Error scraping the website: {e}")

     
    def get_whois_info(self):
        try:
            w = whois.whois(self.domain)
            self.data['WHOIS Info'] = {
                'Domain Name': w.domain_name,
                'Registrar': w.registrar,
                'Creation Date': w.creation_date,
                'Expiration Date': w.expiration_date,
                'Updated Date': w.updated_date,
                'Name Servers': w.name_servers
            }
            logging.info("[+] WHOIS Info retrieved successfully.")
        except Exception as e:
            logging.error(f"[-] Error fetching WHOIS info: {e}")
            self.data['WHOIS Info'] = None

    # Security Headers Check
    def check_security_headers(self):
        try:
            response = requests.get(self.url)
            headers = response.headers
            security_headers = {
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set')
            }
            self.data['Security Headers'] = security_headers
            logging.info("[+] Security Headers analyzed.")
        except Exception as e:
            logging.error(f"[-] Error checking security headers: {e}")

    # Subdomain Enumeration
    def get_subdomains(self):
        try:
            subdomains = sublist3r.main(self.domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False)
            self.data['Subdomains'] = subdomains
            logging.info(f"[+] Subdomains: {len(subdomains)} found.")
        except Exception as e:
            logging.error(f"[-] Error fetching subdomains: {e}")
            self.data['Subdomains'] = None

    # Open Port scanning with Nmap
    def scan_open_ports(self):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(self.data['IP Address'], '1-1024')  # Scans ports 1 to 1024
            self.data['Open Ports'] = scanner[self.data['IP Address']].get('tcp')
            logging.info("[+] Port scanning completed.")
        except Exception as e:
            logging.error(f"[-] Error performing port scan: {e}")

    # Save data to JSON
    def save_data(self):
        try:
            with open(f"{self.domain}_analysis.json", "w") as json_file:
                json.dump(self.data, json_file, indent=4)
            logging.info(f"[+] Data saved to {self.domain}_analysis.json")
        except Exception as e:
            logging.error(f"[-] Error saving data: {e}")

    # Run all analysis methods in separate threads
    def run_analysis(self):
        logging.info(f"[+] Starting analysis for {self.domain}")
        threads = [
            threading.Thread(target=self.get_ip_address),
            threading.Thread(target=self.get_dns_records),
            threading.Thread(target=self.get_ssl_info_detailed),
            threading.Thread(target=self.scrape_website),
            threading.Thread(target=self.get_whois_info),
            threading.Thread(target=self.check_security_headers),
            threading.Thread(target=self.get_subdomains),
            threading.Thread(target=self.scan_open_ports)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.save_data()

# Main function with CLI
def main():
    parser = argparse.ArgumentParser(description="WebSombramini: Web Analysis and Recon Tool by root0emir")
    parser.add_argument("domain", help="Target domain to analyze (e.g., example.com)")
    args = parser.parse_args()

    # Display banner
    WebSombramini.display_banner()
    
    # Run analysis
    analyzer = WebSombramini(args.domain)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()

