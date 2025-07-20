#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LeviInfoga - OSINT Email Recon Tool - Version améliorée
Author: Levi (Enama Eyenoah Aloys Paul Levi)
Contributeur: ChatGPT/robert-sarah
"""

import requests
import socket
import smtplib
import threading
import json
import os
import sys
import time
import random
import csv
import logging
from datetime import datetime
from bs4 import BeautifulSoup
import dns.resolver
import whois
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn

# Configuration logging
logging.basicConfig(filename='leviinfoga.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:102.0) Gecko/20100101 Firefox/102.0",
]

REQUEST_HEADERS = {
    "User-Agent": random.choice(USER_AGENTS),
    "Accept-Language": "en-US,en;q=0.9",
}

REPORT_DIR = "reports"

BANNER = r"""
██╗      ██╗███████╗ ██████╗  ██╗ ██████╗ 
██║      ██║██╔════╝██╔═══██╗███║██╔═══██╗
██║      ██║█████╗  ██║   ██║╚██║██║   ██║
██║      ██║██╔══╝  ██║   ██║ ██║██║   ██║
███████╗ ██║███████╗╚██████╔╝ ██║╚██████╔╝
╚══════╝ ╚═╝╚══════╝ ╚═════╝  ╚═╝ ╚═════╝ 
          [bold green]by Levi[/bold green]
"""

def sanitize_filename(s: str) -> str:
    return "".join(c for c in s if c.isalnum() or c in ("_", "-", "."))

def save_report(email: str, data: dict):
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)
    filename_base = sanitize_filename(email)
    json_path = os.path.join(REPORT_DIR, f"{filename_base}.json")
    txt_path = os.path.join(REPORT_DIR, f"{filename_base}.txt")
    csv_path = os.path.join(REPORT_DIR, f"{filename_base}.csv")
    # JSON
    with open(json_path, "w", encoding="utf-8") as fjson:
        json.dump(data, fjson, indent=4)
    # TXT
    with open(txt_path, "w", encoding="utf-8") as ftxt:
        ftxt.write(f"LeviInfoga Report for {email}\n")
        ftxt.write("=" * 40 + "\n")
        for section, content in data.items():
            ftxt.write(f"\n[{section}]\n")
            if isinstance(content, dict):
                for k, v in content.items():
                    ftxt.write(f"{k}: {v}\n")
            elif isinstance(content, list):
                for item in content:
                    ftxt.write(f"- {item}\n")
            else:
                ftxt.write(str(content) + "\n")
    # CSV
    with open(csv_path, "w", encoding="utf-8", newline='') as fcsv:
        writer = csv.writer(fcsv)
        writer.writerow(['Section', 'Key', 'Value'])
        for section, content in data.items():
            if isinstance(content, dict):
                for k, v in content.items():
                    writer.writerow([section, k, v])
            elif isinstance(content, list):
                for i, item in enumerate(content):
                    writer.writerow([section, f"item_{i+1}", item])
            else:
                writer.writerow([section, '', content])
    console.print(f"[bold green]Reports saved to:[/bold green] {json_path}, {txt_path}, {csv_path}")

def show_report(email: str):
    filename_base = sanitize_filename(email)
    txt_path = os.path.join(REPORT_DIR, f"{filename_base}.txt")
    if os.path.exists(txt_path):
        with open(txt_path, "r", encoding="utf-8") as ftxt:
            console.print(Panel(ftxt.read(), title=f"Report for {email}", style="green"))
    else:
        console.print("[red]No report found. Run 'report' first.[/red]")

def random_delay(min_sec=2, max_sec=5):
    time.sleep(random.uniform(min_sec, max_sec))

def google_search(email: str, max_results=10):
    console.print("[bold cyan]Performing Google search...[/bold cyan]")
    results = []
    api_key = os.getenv('GOOGLE_API_KEY')
    cse_id = os.getenv('GOOGLE_CSE_ID')
    query = f'"{email}"'
    # API usage if key present
    if api_key and cse_id:
        url = f"https://www.googleapis.com/customsearch/v1?q={requests.utils.quote(query)}&num={max_results}&key={api_key}&cx={cse_id}"
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("items", []):
                results.append({
                    "title": item.get("title"),
                    "link": item.get("link"),
                    "snippet": item.get("snippet", "")
                })
        except Exception as e:
            logging.error(f"Google API error: {e}")
            console.print(f"[red]Google API error: {e}[/red]")
    else:
        # Fallback scraping
        url = f"https://www.google.com/search?q={requests.utils.quote(query)}&num={max_results}"
        headers = REQUEST_HEADERS.copy()
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for g in soup.find_all('div', class_='tF2Cxc'):
                title = g.find('h3')
                link = g.find('a')
                snippet = g.find('div', class_='IsZvec')
                if title and link:
                    results.append({
                        "title": title.text.strip(),
                        "link": link['href'],
                        "snippet": snippet.text.strip() if snippet else ""
                    })
        except Exception as e:
            logging.error(f"Google scraping error: {e}")
            console.print(f"[red]Google search error: {e}[/red]")
    random_delay()
    return results

def bing_search(email: str, max_results=10):
    console.print("[bold cyan]Performing Bing search...[/bold cyan]")
    results = []
    api_key = os.getenv('BING_API_KEY')
    query = f'"{email}"'
    if api_key:
        url = f"https://api.bing.microsoft.com/v7.0/search?q={requests.utils.quote(query)}&count={max_results}"
        headers = {"Ocp-Apim-Subscription-Key": api_key, **REQUEST_HEADERS}
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("webPages", {}).get("value", []):
                results.append({
                    "title": item.get("name"),
                    "link": item.get("url"),
                    "snippet": item.get("snippet", "")
                })
        except Exception as e:
            logging.error(f"Bing API error: {e}")
            console.print(f"[red]Bing API error: {e}[/red]")
    else:
        url = f"https://www.bing.com/search?q={requests.utils.quote(query)}&count={max_results}"
        headers = REQUEST_HEADERS.copy()
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for li in soup.find_all('li', class_='b_algo'):
                title = li.find('h2')
                link = title.find('a') if title else None
                snippet = li.find('p')
                if title and link:
                    results.append({
                        "title": title.text.strip(),
                        "link": link['href'],
                        "snippet": snippet.text.strip() if snippet else ""
                    })
        except Exception as e:
            logging.error(f"Bing scraping error: {e}")
            console.print(f"[red]Bing search error: {e}[/red]")
    random_delay()
    return results

def dns_lookup(domain: str):
    console.print(f"[bold cyan]Performing DNS lookup for {domain}[/bold cyan]")
    data = {}
    try:
        answers_mx = dns.resolver.resolve(domain, 'MX', lifetime=5)
        data['MX Records'] = [str(r.exchange).rstrip('.') for r in answers_mx]
    except Exception as e:
        data['MX Records'] = []
        logging.warning(f"MX lookup error for {domain}: {e}")
    try:
        answers_txt = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        spf = []
        for r in answers_txt:
            txt = r.to_text().strip('"')
            if txt.startswith('v=spf1'):
                spf.append(txt)
        data['SPF Records'] = spf
    except Exception as e:
        data['SPF Records'] = []
        logging.warning(f"SPF lookup error for {domain}: {e}")
    data['DKIM Records'] = "Manual check recommended"
    return data

def whois_lookup(domain: str):
    console.print(f"[bold cyan]Performing WHOIS lookup for {domain}[/bold cyan]")
    try:
        w = whois.whois(domain)
        data = {
            "Domain Name": w.domain_name if isinstance(w.domain_name, str) else (w.domain_name[0] if w.domain_name else ""),
            "Registrar": w.registrar,
            "Creation Date": str(w.creation_date) if w.creation_date else "N/A",
            "Expiration Date": str(w.expiration_date) if w.expiration_date else "N/A",
            "Name Servers": w.name_servers if w.name_servers else [],
            "Status": w.status if w.status else "N/A",
            "Emails": w.emails if w.emails else [],
        }
    except Exception as e:
        console.print(f"[red]WHOIS lookup error: {e}[/red]")
        logging.error(f"WHOIS lookup error for {domain}: {e}")
        data = {}
    return data

def smtp_check(email: str):
    console.print(f"[bold cyan]Performing SMTP validation for {email}[/bold cyan]")
    domain = email.split('@')[-1]
    try:
        records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mxRecord = records[0].exchange.to_text()
    except Exception as e:
        console.print(f"[red]Could not resolve MX records: {e}[/red]")
        logging.error(f"SMTP check MX error: {e}")
        return {"SMTP Valid": False, "Reason": "No MX records"}
    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mxRecord)
        server.helo(server.local_hostname)
        sender = f"test{random.randint(1000,9999)}@example.com"
        server.mail(sender)
        code, message = server.rcpt(email)
        server.quit()
        if code == 250:
            return {"SMTP Valid": True, "Reason": "Accepted by server"}
        elif code == 251:
            return {"SMTP Valid": True, "Reason": "User not local, will forward"}
        elif code == 550:
            return {"SMTP Valid": False, "Reason": "Mailbox unavailable"}
        else:
            return {"SMTP Valid": False, "Reason": f"Server returned code {code}"}
    except Exception as e:
        logging.error(f"SMTP check error: {e}")
        return {"SMTP Valid": False, "Reason": f"SMTP error: {e}"}

SOCIAL_PLATFORMS = {
    "Facebook": "https://www.facebook.com/search/top/?q=",
    "Twitter": "https://twitter.com/search?q=",
    "LinkedIn": "https://www.linkedin.com/search/results/all/?keywords=",
    "Instagram": "https://www.instagram.com/",
    "GitHub": "https://github.com/search?q=",
}

def social_media_scan(email: str):
    console.print("[bold cyan]Scanning Social Media platforms (basic)...[/bold cyan]")
    results = []
    user_part = email.split('@')[0]
    for platform, url_base in SOCIAL_PLATFORMS.items():
        if platform == "Instagram":
            url = f"{url_base}{user_part}"
        else:
            url = f"{url_base}{requests.utils.quote(email)}"
        results.append({"platform": platform, "url": url})
    return results

class LeviInfoga:
    def __init__(self):
        self.email = None
        self.results = {}
        self.running = True

    def banner(self):
        console.clear()
        console.print(Panel(BANNER, style="bold green"))

    def help(self):
        table = Table(title="LeviInfoga Commands", show_lines=True)
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_row("help", "Show this help menu")
        table.add_row("show options", "Show current options")
        table.add_row("set email <email>", "Set target email address")
        table.add_row("run", "Run the scan")
        table.add_row("report", "Save scan results to report files")
        table.add_row("show report", "Display the last report in terminal")
        table.add_row("clear", "Clear current target and results")
        table.add_row("exit", "Exit LeviInfoga")
        console.print(table)

    def show_options(self):
        table = Table(title="Current Options", show_lines=True)
        table.add_column("Option", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("email", str(self.email) if self.email else "Not set")
        console.print(table)

    def set_option(self, option: str, value: str):
        if option == "email":
            if "@" not in value or value.count('@') != 1:
                console.print("[red]Invalid email address.[/red]")
                return
            self.email = value.lower()
            console.print(f"[green]Email set to {self.email}[/green]")
        else:
            console.print(f"[red]Unknown option: {option}[/red]")

    def run_scan(self):
        if not self.email:
            console.print("[red]Please set an email address first using `set email <email>`.[/red]")
            return
        self.results = {}
        console.print(f"[bold yellow]Starting scan for {self.email}[/bold yellow]")

        domain = self.email.split("@")[1]

        threads = []

        def google_worker():
            self.results['Google Search'] = google_search(self.email)

        def bing_worker():
            self.results['Bing Search'] = bing_search(self.email)

        def dns_worker():
            self.results['DNS Lookup'] = dns_lookup(domain)

        def whois_worker():
            self.results['WHOIS Lookup'] = whois_lookup(domain)

        def smtp_worker():
            self.results['SMTP Validation'] = smtp_check(self.email)

        def social_worker():
            self.results['Social Media'] = social_media_scan(self.email)

        workers = [google_worker, bing_worker, dns_worker, whois_worker, smtp_worker, social_worker]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            tasks = []
            for worker in workers:
                task = progress.add_task(description=worker.__name__, total=None)
                t = threading.Thread(target=worker)
                threads.append((t, task))
                t.start()

            for t, task in threads:
                t.join()
                progress.remove_task(task)

        console.print("[bold green]Scan complete! Use 'report' to save results or 'show report' to view report.[/bold green]")

    def save_report_cmd(self):
        if not self.email or not self.results:
            console.print("[red]No scan results to save. Run 'run' first.[/red]")
            return
        save_report(self.email, self.results)

    def show_report_cmd(self):
        if not self.email:
            console.print("[red]No email set.[/red]")
            return
        show_report(self.email)

    def clear_cmd(self):
        self.email = None
        self.results = {}
        console.print("[yellow]Cleared target and results.[/yellow]")

    def main_loop(self):
        self.banner()
        while self.running:
            try:
                cmd = Prompt.ask("[bold blue]infoga[/bold blue] >").strip()
                if not cmd:
                    continue
                parts = cmd.split()
                if parts[0].lower() == "help":
                    self.help()
                elif parts[0].lower() == "show" and len(parts) > 1 and parts[1].lower() == "options":
                    self.show_options()
                elif parts[0].lower() == "show" and len(parts) > 1 and parts[1].lower() == "report":
                    self.show_report_cmd()
                elif parts[0].lower() == "set" and len(parts) > 2:
                    self.set_option(parts[1].lower(), " ".join(parts[2:]))
                elif parts[0].lower() == "run":
                    self.run_scan()
                elif parts[0].lower() == "report":
                    self.save_report_cmd()
                elif parts[0].lower() == "clear":
                    self.clear_cmd()
                elif parts[0].lower() == "exit":
                    self.running = False
                    console.print("[bold red]Exiting LeviInfoga. Goodbye![/bold red]")
                else:
                    console.print(f"[red]Unknown command: {cmd}[/red]")
                    console.print("Type 'help' to see available commands.")
            except KeyboardInterrupt:
                console.print("\n[bold red]Interrupted by user. Exiting.[/bold red]")
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                logging.error(f"Main loop error: {e}")

def main():
    tool = LeviInfoga()
    tool.main_loop()

if __name__ == "__main__":
    main()