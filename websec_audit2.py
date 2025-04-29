import os
import subprocess
from datetime import datetime

# Adding colored output with the termcolor module
from termcolor import colored

banner ="""           ===============================
                   websec_audit
           ===============================
           Team Members:
           - Aman
           - Lahari
           - Keerthi
           - Rohit
           ===============================

"""

print(colored(banner, 'green'))

def get_domains():
    user_input = input("Enter a domain or path to a file containing domains: ").strip()
    if os.path.isfile(user_input):
        with open(user_input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        domains = [user_input]
    print(f"[+] Loaded {len(domains)} domain(s).")
    return domains

def show_menu():
    print("\nSelect an option:")
    print("1) Subdomain Enumeration")
    print("2) URL Enumeration")
    print("3) Both Subdomain and URL Enumeration")
    while True:
        try:
            choice = int(input("Enter your choice (1/2/3): "))
            if choice in [1, 2, 3]:
                return choice
            else:
                print("Invalid choice. Please choose 1, 2, or 3.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def run_subdomain_enum(domains):
    for domain in domains:
        domain_dir = domain
        os.makedirs(domain_dir, exist_ok=True)

        print(f"\n[+] Enumerating subdomains for: {domain}")
        subfinder_file = os.path.join(domain_dir, f"{domain}_subfinder.txt")
        assetfinder_file = os.path.join(domain_dir, f"{domain}_assetfinder.txt")
        combined_file = os.path.join(domain_dir, f"{domain}_subdomains.txt")

        print("[-] Running subfinder...")
        subprocess.run(f"subfinder -d {domain} -silent -o {subfinder_file}", shell=True)

        print("[-] Running assetfinder...")
        subprocess.run(f"assetfinder --subs-only {domain} > {assetfinder_file}", shell=True)

        print("[-] Combining and sorting subdomains...")
        all_subs = set()
        for file in [subfinder_file, assetfinder_file]:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    all_subs.update(line.strip() for line in f if line.strip())

        with open(combined_file, 'w') as out:
            for sub in sorted(all_subs):
                out.write(sub + '\n')

        print(f"[+] All subdomains saved to: {combined_file}")

def run_url_enum(domains):
    for domain in domains:
        domain_dir = domain
        os.makedirs(domain_dir, exist_ok=True)

        subdomain_file = os.path.join(domain_dir, f"{domain}_subdomains.txt")
        if not os.path.exists(subdomain_file):
            print(f"[!] Subdomain file not found: {subdomain_file}")
            continue

        print(f"\n[+] Enumerating URLs for domain: {domain}")
        katana_out = os.path.join(domain_dir, f"{domain}_katana.txt")
        gau_out = os.path.join(domain_dir, f"{domain}_gau.txt")
        js_leaks_out = os.path.join(domain_dir, "js_leaks.txt")
        nuclei_out = os.path.join(domain_dir, "js_exposures_results.txt")
        temp_js_file = os.path.join(domain_dir, "temp_all_js.txt")

        with open(subdomain_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]

        all_urls = set()

        for sub in subdomains:
            print(f"[-] Running katana on: {sub}")
            subprocess.run(f"katana -u {sub} -silent >> {katana_out}", shell=True)

            print(f"[-] Running gau on: {sub}")
            subprocess.run(f"gau {sub} >> {gau_out}", shell=True)

        print("[-] Filtering and sorting .js URLs...")
        for file in [katana_out, gau_out]:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url.endswith(".js"):
                            all_urls.add(url)
                            print(f"[+] Found JS URL: {url}")

        with open(temp_js_file, 'w') as js_file:
            for url in sorted(all_urls):
                js_file.write(url + '\n')

        print("[*] Checking which JS URLs are live with httpx...")
        subprocess.run(f"httpx -l {temp_js_file} -mc 200 -silent -o {js_leaks_out}", shell=True)
        print(f"[+] Live JS URLs saved to {js_leaks_out}")

        print("[*] Scanning for JS exposures using Nuclei...")
        subprocess.run(f"nuclei -l {js_leaks_out} -t ~/nuclei-templates/exposures/ -o {nuclei_out}", shell=True)
        print(f"[+] JS exposure scan complete. Results saved to {nuclei_out}")

def generate_report(domains):
    for domain in domains:
        domain_dir = domain
        report_file = os.path.join(domain_dir, f"{domain}_audit_report.txt")

        subdomains = []
        js_urls = []
        js_exposures = []

        subdomain_file = os.path.join(domain_dir, f"{domain}_subdomains.txt")
        if os.path.exists(subdomain_file):
            with open(subdomain_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]

        js_file = os.path.join(domain_dir, "js_leaks.txt")
        if os.path.exists(js_file):
            with open(js_file, 'r') as f:
                js_urls = [line.strip() for line in f if line.strip()]

        exposures_file = os.path.join(domain_dir, "js_exposures_results.txt")
        if os.path.exists(exposures_file):
            with open(exposures_file, 'r') as f:
                js_exposures = [line.strip() for line in f if line.strip()]

        with open(report_file, 'w') as f:
            f.write(f"Audit Report for {domain}\n")
            f.write(f"Generated on {datetime.now()}\n")
            f.write("\n" + "="*50 + "\n")

            f.write(colored("\n[+] Subdomains Found:\n", 'yellow'))
            f.write(f"Total: {len(subdomains)}\n")
            f.writelines(f" - {sub}\n" for sub in subdomains[:10])
            if len(subdomains) > 10:
                f.write("... (truncated)\n")

            f.write(colored("\n[+] Live JS URLs Found:\n", 'yellow'))
            f.write(f"Total: {len(js_urls)}\n")
            f.writelines(f" - {url}\n" for url in js_urls[:10])
            if len(js_urls) > 10:
                f.write("... (truncated)\n")

            f.write(colored("\n[+] Vulnerabilities Detected via Nuclei:\n", 'yellow'))
            f.write(f"Total: {len(js_exposures)}\n")
            f.writelines(f" - {vuln}\n" for vuln in js_exposures[:10])
            if len(js_exposures) > 10:
                f.write("... (truncated)\n")

            f.write("\n" + "="*50 + "\n")
            f.write("\nRecommended Actions:\n")
            f.write("- Review exposed JS files.\n")
            f.write("- Fix vulnerabilities found.\n")
            f.write("- Harden server configurations.\n")

        print(f"[+] Audit report generated: {report_file}")

if __name__ == "__main__":
    domains = get_domains()
    choice = show_menu()
    if choice == 1:
        run_subdomain_enum(domains)
    elif choice == 2:
        run_url_enum(domains)
    elif choice == 3:
        run_subdomain_enum(domains)
        run_url_enum(domains)

    generate_report(domains)
