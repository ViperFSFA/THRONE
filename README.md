
# 🏰 THRONE — Command-Line Pentesting Toolkit

**Created by [ViperFSFA](https://viperfsfa.com)**
**"Hack the planet!"**

---

## ⚠️ Ethical Disclaimer

THRONE is a **pentesting toolkit intended strictly for authorized security testing and educational use**.
You **must have explicit permission** from the owner of any system, network, or domain you test.
The creator and contributors are **not responsible** for any misuse, damage, or unauthorized activity.

---

## 🧠 Overview

**THRONE** is a Python-based command-line pentesting toolkit designed to provide a wide variety of reconnaissance and scanning utilities — all in a single, interactive CLI.

It’s built using libraries like:

* `requests`, `socket`, and `ssl` for network operations
* `BeautifulSoup` for HTML parsing
* `rich` and `colorama` for beautiful terminal output

---

## 🧰 Features

THRONE includes a diverse set of modules for reconnaissance and web security testing:

| Category                | Tools                                            |
| ----------------------- | ------------------------------------------------ |
| **Domain Intelligence** | Domain scan, WHOIS lookup, subdomain enumeration |
| **Network Analysis**    | Reverse IP lookup, IP/GeoIP lookup               |
| **Web Recon**           | Directory scanning, spider crawler               |
| **Protocol Tests**      | HTTP methods scan, DNS zone transfer             |
| **Fingerprinting**      | Banner grabbing, technology fingerprinting       |
| **Security Checks**     | WAF detection, XSS parameter scanning            |

---

## ⚙️ Requirements

THRONE requires **Python 3.8+** and the following dependencies:

```bash
pip install rich colorama requests beautifulsoup4 python-whois dnspython
```

Optional dependencies:

* `geoip2` (for advanced GeoIP support)
* `aiohttp` / `aiodns` (for async modules in future updates)

---

## 🚀 Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/ViperFSFA/THRONE.git
   cd THRONE
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   *(Or manually install the modules listed above.)*

3. **Run THRONE**

   ```bash
   python3 User_Main.py
   ```

---

## 🕹️ Usage

Once launched, you’ll be greeted by the THRONE banner and an interactive prompt:

```bash
user@throne> help
```

### 🔑 Commands

| Command                         | Description                                         |
| ------------------------------- | --------------------------------------------------- |
| `help`                          | Show all commands                                   |
| `scan <domain>`                 | Perform a general domain scan (ports, SSL, headers) |
| `geoip <domain>`                | Lookup GeoIP information for a domain               |
| `iplookup <ip>`                 | Lookup details about an IP address                  |
| `dirscan <domain> [wordlist]`   | Directory scan with optional custom wordlist        |
| `whois <domain>`                | WHOIS lookup                                        |
| `spider <domain>`               | Web crawler to discover links                       |
| `subdomain <domain> [wordlist]` | Subdomain enumeration                               |
| `reverseip <domain>`            | Reverse IP lookup (find hosted domains)             |
| `httpmethods <domain>`          | Enumerate supported HTTP methods                    |
| `zonetransfer <domain>`         | Test for DNS zone transfer vulnerabilities          |
| `bannergrab <domain> <port>`    | Grab service banners from open ports                |
| `techfinger <domain>`           | Detect technologies (headers, frameworks, etc.)     |
| `wafdetect <domain>`            | Detect Web Application Firewalls                    |
| `findxss <domain>`              | Detect potential XSS injection points               |
| `about`                         | Display information about THRONE                    |
| `exit / quit`                   | Exit the CLI                                        |

---

## 🧩 Example Sessions

### Scan a domain

```bash
user@throne> scan example.com
```

### Lookup WHOIS info

```bash
user@throne> whois example.com
```

### Run a GeoIP lookup

```bash
user@throne> geoip example.com
```

### Directory scan using a custom wordlist

```bash
user@throne> dirscan example.com ./wordlists/common.txt
```

---

## 🧾 Output Example

```
[cyan]DNS:[/cyan] example.com resolves to [bold]93.184.216.34[/bold]
[green]http://example.com : UP (Status 200)[/green]
[bold magenta]Port Scan:[/bold magenta]
  [green]80 OPEN (HTTP)[/green]
  [red]22 CLOSED (SSH)[/red]
[bold blue]SSL:[/bold blue] Subject: example.com, Issuer: Let's Encrypt
```

---

## ⚔️ Credits

**Author:** ViperFSFA
**Website:** [ViperFSFA.com](https://viperfsfa.com) 
