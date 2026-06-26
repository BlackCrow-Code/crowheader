import argparse
import requests
import pyfiglet
from rich.console import Console
from rich.table import Table

try:
    # 1. Parsing command-line arguments
    parse = argparse.ArgumentParser(description="crowheader - Checks Headers")
    parse.add_argument("-u", "--url", required=True, help="Uniform Resource Locator [URL]")
    parse.add_argument("-t", "--threads", default=10, type=int, help="Number of threads")
    parse.add_argument("--CS", action="store_true", help="Client Side Headers")
    parse.add_argument("--N", action="store_true", help="Network Headers")
    parse.add_argument("--D", action="store_true", help="Disclosure Headers")
    parse.add_argument("-c", "--custom", type=str, help="Select your custom headers file")

    args = parse.parse_args()

    # Clean up target URL format
    url = args.url.strip("/")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Target security intelligence profiles
    client_side_headers = [
        "X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options",
        "Access-Control-Allow-Origin", "Cross-Origin-Opener-Policy", 
        "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"
    ]

    network_headers = [
        "Strict-Transport-Security", "Cache-Control", "Clear-Site-Data"
    ]

    disclosure_headers = [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime",
        "X-Backend-Server", "X-Cache", "CF-Ray", "X-Varnish"
    ]

    missing_cs_summary = []
    missing_n_summary = []
    leaks_summary = []
    custom_summary = []

    # Load custom headers wordlist if provided
    custom_headers = []
    if args.custom:
        try:
            with open(args.custom, "r", errors="ignore") as f:
                custom_headers = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Error: File {args.custom} not found.")
            exit(1)
            
    # 2. Rendering UI Banner and Target Information
    console = Console()
    crowheader_banner = pyfiglet.figlet_format("crowheader", font="slant") # Fixed to lowercase
    console.print(f"[bold cyan]{crowheader_banner}[/bold cyan]")
    console.print(f"[bright_white][*]Target:[/bright_white] [cyan]{url}[/cyan]")

    if args.threads != 10:
        console.print(f"[bright_white][*]threads:[/bright_white] [cyan]{args.threads}[/cyan]")
    else:
        console.print(f"[bright_white][*]threads: default({args.threads})[/bright_white]") 

    console.print(f"[bright_white][*]headers:[/bright_white] [cyan]{"[bright_yellow]| Custom Headers |[/bright_yellow]" if args.custom else ''}{f"| Client Side Headers |" if args.CS else ''}{f"| Disclosure Headers |" if args.D else ''}{f"| Network Headers |" if args.N else ''}[/cyan][bright_white]{f"default (all) " if not args.CS and not args.D and not args.N and not args.custom else ''}[/bright_white]")

    # 3. Auditing core logic
    def check_cs(r):
        console.print("\n[bold white]---> Client Side Headers Check <---[/bold white]")
        for header in client_side_headers:
            if header in r:
                console.print(f"[bold green][+] FOUND:[/bold green] {header}")
            else:
                console.print(f"[bold red][-] MISSING:[/bold red] {header} [yellow](Vulnerable To Clickjacking/XSS)[/yellow]")
                missing_cs_summary.append(header)

    def check_N(r):
        console.print("\n[bold white]---> Network Headers Check <---[/bold white]")
        for header in network_headers:
            if header in r:
                console.print(f"[bold blue][+] FOUND:[/bold blue] {header}")            
            else:
                console.print(f"[bold red][-] MISSING:[/bold red] {header} [yellow](Vulnerable to MITM/Caching Leaks)[/yellow]")            
                missing_n_summary.append(header)

    def check_D(r):
        console.print("\n[bold white]---> Disclosure Headers Check <---[/bold white]")
        found_leak = False
        for header in disclosure_headers:
            if header in r:
                console.print(f"[bold red][!] DETECTED LEAK:[/bold red] {header} -> [bright_yellow]{r[header]}[/bright_yellow]") 
                leaks_summary.append(f"{header} ({r[header]})")
                found_leak = True
        if not found_leak:
            console.print("[bold green][+] SAFE:[/bold green] No backend metadata leaks detected.")

    def check_custom(r):
        console.print("\n[bold white]---> Custom Headers Check <---[/bold white]")
        for header in custom_headers:
            if header in r:
                console.print(f"[bold yellow][+] CUSTOM FOUND:[/bold yellow] {header} -> [bright_white]{r[header]}[/bright_white]")  
                custom_summary.append(header)

    # 4. Triggering connection and scanning workflow
    try:
        s = requests.Session()
        console.print(f"\n[bright_white][*] Connecting to target...[/bright_white]")
        
        with console.status("[bold cyan]Starting Headers Check...", spinner="dots"):
            rp = s.head(url, timeout=5, allow_redirects=True)
            r = rp.headers
            
        console.print("[bold green][+] Connection established successfully![/bold green]")

        run_all = not args.CS and not args.N and not args.D and not args.custom

        if args.CS or run_all:
            check_cs(r) 
        if args.N or run_all:
            check_N(r)
        if args.D or run_all:
            check_D(r)           
        if args.custom:
            check_custom(r)

        # 5. Executive Summary Table
        console.print("\n")
        summary_table = Table(title="[bold cyan]💀 CROWHEADER SCAN REPORT 💀[/bold cyan]", show_header=True, header_style="bold magenta", expand=True)
        summary_table.add_column("Category Target", justify="left", style="cyan")
        summary_table.add_column("Findings Log / Status Report", justify="left")
        
        if missing_cs_summary:
            summary_table.add_row("Missing Client-Side Protection", f"[bold red][!] Vulnerable:[/bold red] Missing {missing_cs_summary}")
        else:
            summary_table.add_row("Missing Client-Side Protection", "[bold green][+] Secure (All headers present)[/bold green]")
            
        if missing_n_summary:
            summary_table.add_row("Missing Network/Transport Security", f"[bold red][!] Vulnerable:[/bold red] Missing {missing_n_summary}")
        else:
            summary_table.add_row("Missing Network/Transport Security", "[bold green][+] Secure (All headers present)[/bold green]")
            
        if leaks_summary:
            summary_table.add_row("Information Disclosure Leaks", f"[bold orange3][!] Detected:[/bold orange3] Exposed {leaks_summary}")
        else:
            summary_table.add_row("Information Disclosure Leaks", "[bold green][+] Hardened (No backend infrastructure leaked)[/bold green]")
            
        if args.custom:
            if custom_summary:
                summary_table.add_row("Custom Signature Profiles", f"[bold yellow][*] Matches Found:[/bold yellow] {custom_summary}")
            else:
                summary_table.add_row("Custom Signature Profiles", "[bold white][-] No matches found in your file[/bold white]")

        console.print(summary_table)
        console.print(f"\n[bold cyan][*] Scan finished for {url}. Good hunting.[/bold cyan]\n")

    except requests.RequestException:
        console.print(f"\n[bold red][X] Can't connect with {url}[/bold red]")
        exit(1)

except KeyboardInterrupt:
    # Catching Ctrl+C and exiting cleanly without ugly errors
    print("\n\n[-] Operation cancelled by user. Exiting crowheader...")
    exit(0)
