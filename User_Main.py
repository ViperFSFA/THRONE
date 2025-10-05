# This is a command-line pentesting toolkit named THRONE, created by ViperFSFA.
# It includes various tools for scanning domains, performing WHOIS lookups, directory scanning,
# subdomain enumeration, web spidering, and more. The code uses libraries like requests, socket,
# ssl, and BeautifulSoup for network operations and HTML parsing.

# A tool made by ViperFSFA
# Hacktheplanet!


import sys
try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.prompt import Prompt
except ImportError:
    print("Missing dependency: rich. Install with: pip install rich")
    sys.exit(1)

try:
    from colorama import init
except ImportError:
    print("Missing dependency: colorama. Install with: pip install colorama")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency: beautifulsoup4. Install with: pip install beautifulsoup4")
    sys.exit(1)

import socket
import ssl
import os
import subprocess
from urllib.parse import urljoin, urlparse

init(autoreset=True)
console = Console()

class ThroneCLI:
    def __init__(self):
        self.Destruction_Model = "Default"
        class OptionParser:
            description = "Welcome to THRONE - Command Line pentesting toolkit by ViperFSFA."
        self.optionParser = OptionParser()

    def banner_welcome(self):
        evil_banner = [
            "                     ____                                                                        ",
            "          ||        / /\\ \\      ||              #===============================================#",
            "        -(00)-     + (XX) +   -(00)-            ||                                             ||",
            "   ||     ||   O ==*~~~~~~*== 0 ||        ||    ||  > Main [Tools]     #  > secondary          ||",
            " -(00)-     O|O  (0)  XX  (0)           -(00)-  ||                                             ||",
            "   ||  _____ |____\\| (00) |/______|D___   ||    ||     |-> SCAN        #     |-> GEOIP         ||",
            "     O+!$(O)! (O)  0'----'0  (O) !(O)$!+O       ||     |-> DIRSCAN     #     |-> WHOIS         ||",   
            "       |OO OO|  .''.( xx ).''.  |OO OO|         ||     |-> SPIDER      #     |-> SUBDOMAIN     ||",
            "      **+***.'.'  +X|'..'|X+  '.'***+**.        ||     |-> REVERSEIP   #     |-> IPLOOKUP      ||",
            "     .-.  .' /'--.__|_00_|__.--'\\ '.  .-.       ||     |-> HTTPMETHODS #     |-> ZONETRANSFER  ||",
            "   +(O).)-|0|  \\   x| ## |x   /  |0|-(.(O)+     ||     |-> XSSPARAMS    #                      ||",
            "     `-'  '-'-._'-./ -00- \\.-'_.-'-'  `-'       ||     |-> WAFDETECT   #     |-> HELP          ||",
            "        _ | ||  '-.___||___.-'  || | _          ||     |-> ABOUT        #     |-> EXIT         ||",
            "     .' _ | ||==O |   __   | O==|| | _ '.       ||                                             ||",
            "    / .' ''.|  || | /_00_\\ | ||  |.'' '. \\      ||                                             ||",
            " _  | '###  |  =| | ###### | |=  |' ###  |  _   ||                                             ||",
            "(0)-| |(0)| '.  0\\||__**_ ||/0  .' |(0)| |-(0)  ||                                             ||",
            " *  \\ '._.'   '.  | \\_##_/ |  .'   '._.' /  *   ||                                             ||",
            "     '.__ ____0_'.|__'--'__|.'_0____ __.'       #|=============================================|#",
            "    .'_.-|            YY            |-._'.      ||                                             ||",
            "                                                ||  ->       [ Web: ViperFSFA.com ]        <-  ||", 
            "                                                ||                                             ||",
            "                                                #|=============================================|#"
        ]
        for i, line in enumerate(evil_banner):
            r = min(255, 100 + i * 5)
            b = min(255, int(i * 7))
            color = f"rgb({r},0,{b})"
            console.print(Text(line, style=f"bold {color}"))
        print("")

    def banner(self):
        banner_lines = [
            "▄▄▄█████▓ ██░ ██  ██▀███   ▒█████   ███▄    █ ▓█████ ",
            "▓  ██▒ ▓▒▓██░ ██▒▓██ ▒ ██▒▒██▒  ██▒ ██ ▀█   █ ▓█   ▀ ",
            "▒ ▓██░ ▒░▒██▀▀██░▓██ ░▄█ ▒▒██░  ██▒▓██  ▀█ ██▒▒███   ",
            "░ ▓██▓ ░ ░▓█ ░██ ▒██▀▀█▄  ▒██   ██░▓██▒  ▐▌██▒▒▓█  ▄ ",
            "  ▒██▒ ░ ░▓█▒░██▓░██▓ ▒██▒░ ████▓▒░▒██░   ▓██░░▒████▒",
            "  ▒ ░░    ▒ ░░▒░▒░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░░ ▒░ ░",
            "    ░     ▒ ░▒░ ░  ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░░   ░ ▒░ ░ ░  ░", 
            "  ░       ░  ░░ ░  ░░   ░ ░ ░ ▒     ░   ░ ░    ░   ",
            "          ░  ░  ░   ░         ░ ░           ░    ░  ░"
        ]
        for i, line in enumerate(banner_lines):
            r = min(255, 80 + 20 * i)
            color = f"rgb({r},0,0)"
            console.print(Text(line, style=f"bold {color}"))
        console.print(Text(self.optionParser.description, style="bold red"))
        console.rule("=" * 50)

    def scan_domain(self, domain):
        protocols = ["http://", "https://"]
        results = []

        # HTTP/HTTPS status check
        for proto in protocols:
            url = proto + domain
            try:
                response = requests.get(url, timeout=5)
                status = f"[green]UP[/green]" if response.status_code < 400 else f"[yellow]WARN[/yellow]"
                results.append(f"{url} : {status} (Status {response.status_code})")
            except requests.exceptions.RequestException as e:
                results.append(f"{url} : [red]DOWN[/red] ({e.__class__.__name__})")

        # DNS resolution
        try:
            ip = socket.gethostbyname(domain)
            results.append(f"[cyan]DNS:[/cyan] {domain} resolves to [bold]{ip}[/bold]")
        except Exception as e:
            results.append(f"[red]DNS:[/red] Could not resolve domain ({e.__class__.__name__})")

        # Port scan (common ports)
        common_ports = {
            21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT"
        }
        results.append("[bold magenta]Port Scan (top ports):[/bold magenta]")
        for port, name in common_ports.items():
            try:
                sock = socket.create_connection((domain, port), timeout=1)
                results.append(f"  [green]{port} OPEN[/green] ({name})")
                sock.close()
            except Exception:
                results.append(f"  [red]{port} CLOSED[/red] ({name})")

        # SSL certificate info (if HTTPS)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    results.append(f"[bold blue]SSL:[/bold blue] Subject: {subject.get('commonName', 'N/A')}, Issuer: {issuer.get('commonName', 'N/A')}")
        except Exception as e:
            results.append(f"[yellow]SSL:[/yellow] No certificate info ({e.__class__.__name__})")

        # HTTP headers
        try:
            response = requests.get("http://" + domain, timeout=5)
            headers = response.headers
            results.append("[bold green]HTTP Headers:[/bold green]")
            for k, v in headers.items():
                results.append(f"  [cyan]{k}[/cyan]: {v}")
        except Exception:
            results.append("[yellow]Could not fetch HTTP headers[/yellow]")

        # Print all results
        for line in results:
            console.print(line)

    def geoip_lookup(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                console.print(f"[bold magenta]GeoIP Lookup for {domain} ({ip}):[/bold magenta]")
                for key in ["city", "region", "country", "org", "loc"]:
                    if key in data:
                        console.print(f"[cyan]{key.capitalize()}:[/cyan] {data[key]}")
            else:
                console.print("[red]GeoIP lookup failed (bad response)[/red]")
        except Exception as e:
            console.print(f"[red]GeoIP lookup failed: {e}[/red]")

    def dirscan(self, domain, wordlist_path=""):
        # Use a default wordlist if none provided
        default_paths = [
            "admin", "login", "dashboard", "config", "uploads", "images", "js", "css", "api", "backup", "test", "dev", "old", "private", "data", "robots.txt"
        ]
        paths = []
        if wordlist_path and os.path.isfile(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                paths = [line.strip() for line in f if line.strip()]
        else:
            paths = default_paths

        console.print(f"[bold magenta]Directory scan on:[/bold magenta] [cyan]{domain}[/cyan]")
        found = False
        for path in paths:
            for proto in ["http://", "https://"]:
                url = f"{proto}{domain}/{path}"
                try:
                    r = requests.get(url, timeout=3)
                    if r.status_code < 400:
                        console.print(f"[green]{url}[/green] [bold]({r.status_code})[/bold]")
                        found = True
                except Exception:
                    pass
        if not found:
            console.print("[yellow]No common directories found.[/yellow]")

    def whois_lookup(self, domain):
        try:
            import whois
        except ImportError:
            console.print("[red]whois module not installed. Run: pip install python-whois[/red]")
            return
        try:
            w = whois.whois(domain)
            console.print(f"[bold magenta]WHOIS Lookup for {domain}:[/bold magenta]")
            for key in ["domain_name", "registrar", "creation_date", "expiration_date", "name_servers", "org", "country"]:
                value = w.get(key)
                if value:
                    console.print(f"[cyan]{key.replace('_', ' ').title()}:[/cyan] {value}")
        except Exception as e:
            console.print(f"[red]WHOIS lookup failed: {e}[/red]")

    def web_spider(self, domain, max_pages=30):
        visited = set()
        to_visit = [f"http://{domain}"]
        found_links = set()
        console.print(f"[bold magenta]Web Spider starting at:[/bold magenta] [cyan]{domain}[/cyan]")
        count = 0

        while to_visit and count < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code >= 400:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc and domain in parsed.netloc:
                        if full_url not in visited and full_url not in to_visit:
                            to_visit.append(full_url)
                        found_links.add(full_url)
                count += 1
            except Exception:
                continue

        if found_links:
            console.print(f"[bold green]Found links ({len(found_links)}):[/bold green]")
            for link in sorted(found_links):
                console.print(f"[cyan]{link}[/cyan]")
        else:
            console.print("[yellow]No links found or site not reachable.[/yellow]")

    def subdomain_enum(self, domain, wordlist_path=""):
        default_subs = ["www", "mail", "ftp", "test", "dev", "admin", "api", "blog", "shop"]
        subs = []
        if wordlist_path and os.path.isfile(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                subs = [line.strip() for line in f if line.strip()]
        else:
            subs = default_subs

        console.print(f"[bold magenta]Subdomain enumeration for:[/bold magenta] [cyan]{domain}[/cyan]")
        found = False
        for sub in subs:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                console.print(f"[green]{subdomain}[/green] -> [bold]{ip}[/bold]")
                found = True
            except Exception:
                pass
        if not found:
            console.print("[yellow]No subdomains found.[/yellow]")

    def reverse_ip(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            # Using hackertarget API for demonstration (public, limited)
            response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=8)
            if response.status_code == 200:
                data = response.text.strip()
                if "error" in data.lower() or not data:
                    console.print(f"[yellow]No domains found for IP {ip}[/yellow]")
                else:
                    domains = data.splitlines()
                    console.print(f"[bold magenta]Reverse IP Lookup for {domain} ({ip}):[/bold magenta]")
                    for d in domains:
                        console.print(f"[cyan]{d}[/cyan]")
            else:
                console.print("[red]Reverse IP lookup failed (bad response)[/red]")
        except Exception as e:
            console.print(f"[red]Reverse IP lookup failed: {e}[/red]")

    def ip_lookup(self, ip):
        """Lookup info for an IP address using ipinfo.io"""
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                console.print(f"[bold magenta]IP Lookup for {ip}:[/bold magenta]")
                for key in ["city", "region", "country", "org", "loc", "hostname"]:
                    if key in data:
                        console.print(f"[cyan]{key.capitalize()}:[/cyan] {data[key]}")
            else:
                console.print("[red]IP lookup failed (bad response)[/red]")
        except Exception as e:
            console.print(f"[red]IP lookup failed: {e}[/red]")

    def http_methods(self, domain):
        url = f"http://{domain}"
        try:
            resp = requests.options(url, timeout=5)
            methods = resp.headers.get("Allow", "")
            if methods:
                console.print(f"[bold magenta]Allowed HTTP methods for {domain}:[/bold magenta] [cyan]{methods}[/cyan]")
            else:
                console.print("[yellow]No Allow header found. Try manual testing.[/yellow]")
        except Exception as e:
            console.print(f"[red]HTTP method scan failed: {e}[/red]")

    def dns_zone_transfer(self, domain):
        try:
            import dns.resolver, dns.query, dns.zone
        except ImportError:
            console.print("[red]dnspython module not installed. Run: pip install dnspython[/red]")
            return
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_addr = str(ns.target)
                console.print(f"[bold magenta]Trying zone transfer on {ns_addr}...[/bold magenta]")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, domain, timeout=5))
                    for name, node in zone.nodes.items():
                        console.print(f"[cyan]{name}[/cyan]")
                    return
                except Exception:
                    continue
            console.print("[yellow]Zone transfer failed or not allowed.[/yellow]")
        except Exception as e:
            console.print(f"[red]DNS zone transfer test failed: {e}[/red]")

    def banner_grab(self, domain, port=80):
        try:
            with socket.create_connection((domain, port), timeout=3) as sock:
                sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore")
                console.print(f"[bold magenta]Banner for {domain}:{port}:[/bold magenta]\n[cyan]{banner.strip()}[/cyan]")
        except Exception as e:
            console.print(f"[red]Banner grab failed: {e}[/red]")

    def tech_fingerprint(self, domain):
        url = f"http://{domain}"
        try:
            resp = requests.get(url, timeout=5)
            headers = resp.headers
            console.print(f"[bold magenta]Technology fingerprint for {domain}:[/bold magenta]")
            for key in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Drupal-Cache"]:
                if key in headers:
                    console.print(f"[cyan]{key}:[/cyan] {headers[key]}")
        except Exception as e:
            console.print(f"[red]Tech fingerprint failed: {e}[/red]")

    def waf_detect(self, domain):
        """Detect possible Web Application Firewall by checking headers and responses."""
        url = f"http://{domain}"
        try:
            resp = requests.get(url, timeout=5)
            waf_signatures = [
                ("cloudflare", "Cloudflare"),
                ("sucuri", "Sucuri"),
                ("incapsula", "Incapsula"),
                ("akamai", "Akamai"),
                ("f5", "F5 BIG-IP"),
                ("mod_security", "ModSecurity"),
                ("aws", "AWS WAF"),
                ("barracuda", "Barracuda"),
                ("imperva", "Imperva"),
                ("citrix", "Citrix"),
            ]
            found = []
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            for sig, name in waf_signatures:
                for k, v in headers.items():
                    if sig in k or sig in v:
                        found.append(name)
            if found:
                console.print(f"[bold magenta]WAF Detected on {domain}:[/bold magenta] [cyan]{', '.join(set(found))}[/cyan]")
            else:
                console.print(f"[yellow]No obvious WAF detected for {domain}.[/yellow]")
        except Exception as e:
            console.print(f"[red]WAF detection failed: {e}[/red]")

    def find_xss_params(self, domain):
        """Find URLs with parameters and suggest XSS payloads."""
        try:
            resp = requests.get(f"http://{domain}", timeout=5)
            soup = BeautifulSoup(resp.text, "html.parser")
            links = set()
            for tag in soup.find_all("a", href=True):
                href = tag['href']
                if "?" in href and "=" in href:
                    full_url = urljoin(f"http://{domain}", href)
                    links.add(full_url)
            if links:
                console.print(f"[bold magenta]Potential XSS test points on {domain}:[/bold magenta]")
                for url in links:
                    console.print(f"[cyan]{url}[/cyan]")
                console.print("[yellow]Try appending payloads like:[/yellow] [green]<script>alert(1)</script>[/green]")
            else:
                console.print("[yellow]No parameterized links found on the homepage.[/yellow]")
        except Exception as e:
            console.print(f"[red]XSS parameter scan failed: {e}[/red]")

    def prompt(self):
        help_info = [
            "[bold red]THRONE CLI Help[/bold red]",
            "[bold]Available commands:[/bold]",
            "[bold yellow]help[/bold yellow], [bold yellow]-h[/bold yellow]      Show this help message",
            "[bold yellow]exit[/bold yellow], [bold yellow]quit[/bold yellow]     Exit the program",
            "[bold yellow]about[/bold yellow]           About this tool",
            "[bold yellow]scan <domain>[/bold yellow]   Scan a domain",
            "[bold yellow]geoip <domain>[/bold yellow]  GeoIP lookup for a domain",
            "[bold yellow]iplookup <ip>[/bold yellow]   IP address lookup",
            "[bold yellow]dirscan <domain> [wordlist][/bold yellow]  Directory brute force (optional wordlist)",
            "[bold yellow]whois <domain>[/bold yellow]  WHOIS lookup for a domain",
            "[bold yellow]spider <domain>[/bold yellow] Web spider/crawler (find links)",
            "[bold yellow]subdomain <domain> [wordlist][/bold yellow]  Subdomain enumeration (optional wordlist)",
            "[bold yellow]reverseip <domain>[/bold yellow]  Reverse IP lookup (find hosted domains)",
            "[bold yellow]httpmethods <domain>[/bold yellow]  Scan allowed HTTP methods",
            "[bold yellow]zonetransfer <domain>[/bold yellow]  DNS zone transfer test",
            "[bold yellow]bannergrab <domain> <port>[/bold yellow]  Banner grabbing (default port 80)",
            "[bold yellow]techfinger <domain>[/bold yellow]  Technology fingerprinting",
            "[bold yellow]wafdetect <domain>[/bold yellow]  Web Application Firewall detection",
            "[bold yellow]findxss <domain>[/bold yellow]  Find potential XSS parameters"
        ]
        
        console.rule("[bold green]THRONE Command Prompt[/bold green]")
        while True:
            try:
                cmd = console.input("[bold red]user@throne> [/bold red]")
                cmd_lower = cmd.strip().lower()
                if cmd_lower in ("exit", "quit"):
                    print("Exiting THRONE...")
                    break
                elif cmd_lower in ("help", "-h"):
                    help_panel = Panel("\n".join(help_info), title="[bold red]THRONE Help", expand=False)
                    console.print(help_panel)
                elif cmd_lower == "about":
                    about_panel = Panel("[bold red]THRONE[/bold red] is a command-line pentesting toolkit by ViperFSFA.\nHacktheplanet!", title="About", expand=False)
                    console.print(about_panel)
                elif cmd_lower.startswith("scan "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.scan_domain(parts[1])
                    else:
                        console.print("[red]Usage: scan <domain>[/red]")
                elif cmd_lower.startswith("geoip "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.geoip_lookup(parts[1])
                    else:
                        console.print("[red]Usage: geoip <domain>[/red]")
                elif cmd_lower.startswith("iplookup "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.ip_lookup(parts[1])
                    else:
                        console.print("[red]Usage: iplookup <ip>[/red]")
                elif cmd_lower.startswith("dirscan "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.dirscan(parts[1])
                    elif len(parts) == 3:
                        self.dirscan(parts[1], parts[2])
                    else:
                        console.print("[red]Usage: dirscan <domain> [wordlist][/red]")
                elif cmd_lower.startswith("whois "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.whois_lookup(parts[1])
                    else:
                        console.print("[red]Usage: whois <domain>[/red]")
                elif cmd_lower.startswith("spider "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.web_spider(parts[1])
                    else:
                        console.print("[red]Usage: spider <domain>[/red]")
                elif cmd_lower.startswith("subdomain "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.subdomain_enum(parts[1])
                    elif len(parts) == 3:
                        self.subdomain_enum(parts[1], parts[2])
                    else:
                        console.print("[red]Usage: subdomain <domain> [wordlist][/red]")
                elif cmd_lower.startswith("reverseip "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.reverse_ip(parts[1])
                    else:
                        console.print("[red]Usage: reverseip <domain>[/red]")
                elif cmd_lower.startswith("httpmethods "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.http_methods(parts[1])
                    else:
                        console.print("[red]Usage: httpmethods <domain>[/red]")
                elif cmd_lower.startswith("zonetransfer "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.dns_zone_transfer(parts[1])
                    else:
                        console.print("[red]Usage: zonetransfer <domain>[/red]")
                elif cmd_lower.startswith("bannergrab "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.banner_grab(parts[1])
                    elif len(parts) == 3:
                        try:
                            port = int(parts[2])
                        except ValueError:
                            console.print("[red]Port must be an integer[/red]")
                            continue
                        self.banner_grab(parts[1], port)
                    else:
                        console.print("[red]Usage: bannergrab <domain> <port>[/red]")
                elif cmd_lower.startswith("techfinger "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.tech_fingerprint(parts[1])
                    else:
                        console.print("[red]Usage: techfinger <domain>[/red]")
                elif cmd_lower.startswith("wafdetect "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.waf_detect(parts[1])
                    else:
                        console.print("[red]Usage: wafdetect <domain>[/red]")
                elif cmd_lower.startswith("findxss "):
                    parts = cmd.strip().split()
                    if len(parts) == 2:
                        self.find_xss_params(parts[1])
                    else:
                        console.print("[red]Usage: findxss <domain>[/red]")
                elif cmd.strip() == "":
                    continue
                else:
                    console.print(f"[red]Unknown command:[/red] {cmd}")
            except KeyboardInterrupt:
                print("\nExiting THRONE...")
                break
            except EOFError:
                print("\nExiting THRONE...")
                break

    def finishing_touches(self):
        goodbye_text = "[bold green]Thanks for using THRONE! Stay stealthy, stay safe.[/bold green]"
        panel = Panel(goodbye_text, title="[bold red]Goodbye[/bold red]", border_style="bright_magenta")
        console.print(panel)

if __name__ == "__main__":
    cli = ThroneCLI()
    cli.banner_welcome()
    cli.banner()
    cli.prompt()
    cli.finishing_touches()