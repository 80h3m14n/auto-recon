import os
import subprocess
import requests
import json
import time
from datetime import datetime
import argparse
import sys

# Global variables for logging
LOG_DIR = "results"
os.makedirs(LOG_DIR, exist_ok=True)


def log_message(message, log_file):
    """Log messages to a file with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def log_section_header(section, log_file):
    header = f"\n{'='*30}\n[SECTION] {section}\n{'='*30}\n"
    with open(log_file, "a") as f:
        f.write(header)


def run_command(command, log_file):
    """Run a shell command and log the output."""
    log_message(f"Running command: {command}", log_file)
    try:
        result = subprocess.run(command, shell=True,
                                capture_output=True, text=True)
        log_message(f"Command output:\n{result.stdout}", log_file)
        if result.stderr:
            log_message(f"Command error:\n{result.stderr}", log_file)
        return result.stdout
    except Exception as e:
        log_message(f"Command failed: {e}", log_file)
        return None


def gather_public_data(target, log_file, summary):
    log_section_header("Public Data Gathering", log_file)
    log_message("Starting public data gathering...", log_file)
    sources = {
        "OSINT Framework": "https://osintframework.com/",
        "Exploit-DB": "https://www.exploit-db.com/",
        "Pastebin": "https://pastebin.com/",
        "Wayback Machine": "https://web.archive.org/"
    }
    summary['public_data'] = []
    for name, url in sources.items():
        log_message(f"Checking {name}: {url}", log_file)
        summary['public_data'].append({"source": name, "url": url})


def check_certificates(target, log_file, summary):
    log_section_header("Certificate Check", log_file)
    log_message("Checking SSL certificates...", log_file)
    crt_sh_url = f"https://crt.sh/?q={target}"
    censys_url = f"https://censys.io/domain/{target}"
    log_message(f"CRT.sh: {crt_sh_url}", log_file)
    log_message(f"Censys: {censys_url}", log_file)
    summary['certificates'] = {
        "crt.sh": crt_sh_url,
        "censys": censys_url
    }


def enumerate_subdomains(target, log_file, summary):
    log_section_header("Subdomain Enumeration", log_file)
    log_message("Enumerating subdomains...", log_file)
    tools = {
        "Amass": f"amass enum -d {target} -o {LOG_DIR}/amass_results.txt",
        "Sublist3r": f"sublist3r -d {target} -o {LOG_DIR}/sublist3r_results.txt",
        "Subfinder": f"subfinder -d {target} -o {LOG_DIR}/subfinder_results.txt"
    }
    summary['subdomains'] = {}
    for tool, command in tools.items():
        log_message(f"Running {tool}...", log_file)
        run_command(command, log_file)
        result_file = command.split("-o")[-1].strip()
        found = []
        if os.path.exists(result_file):
            with open(result_file) as f:
                lines = [line.strip() for line in f if line.strip()]
                found = lines
            log_message(f"{tool} found {len(found)} subdomains.", log_file)
        else:
            log_message(f"{tool} result file not found.", log_file)
        summary['subdomains'][tool] = {
            "count": len(found),
            "result_file": result_file,
            "subdomains": found[:10]  # Only show first 10 for summary
        }


def identify_technologies(target, log_file, summary):
    log_section_header("Technology Identification", log_file)
    log_message("Identifying technologies...", log_file)
    tools = {
        "BuiltWith": f"curl -s https://builtwith.com/{target}",
        "Wappalyzer": f"wappalyzer {target}",
        "WhatWeb": f"whatweb {target}"
    }
    summary['technologies'] = {}
    for tool, command in tools.items():
        log_message(f"Running {tool}...", log_file)
        output = run_command(command, log_file)
        summary['technologies'][tool] = output.strip()[
            :200] if output else "No output"


def scan_vulnerabilities(target, log_file, summary):
    log_section_header("Vulnerability Scanning", log_file)
    log_message("Scanning for vulnerabilities...", log_file)
    tools = {
        "Nmap": f"nmap -A -T4 {target} -oN {LOG_DIR}/nmap_results.txt",
        "Nikto": f"nikto -h {target} -output {LOG_DIR}/nikto_results.txt"
    }
    summary['vulnerabilities'] = {}
    for tool, command in tools.items():
        log_message(f"Running {tool}...", log_file)
        run_command(command, log_file)
        result_file = command.split(
            "-oN")[-1].strip() if "-oN" in command else command.split("-output")[-1].strip()
        findings = []
        if os.path.exists(result_file):
            with open(result_file) as f:
                findings = [line.strip() for line in f if line.strip()]
            log_message(
                f"{tool} scan completed. Results saved to {result_file}", log_file)
        else:
            log_message(f"{tool} result file not found.", log_file)
        summary['vulnerabilities'][tool] = {
            "result_file": result_file,
            "summary": findings[:10]  # Only show first 10 lines for summary
        }


def export_summary_json(summary, target):
    json_file = os.path.join(
        LOG_DIR, f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_summary.json")
    with open(json_file, "w") as f:
        json.dump(summary, f, indent=2)
    return json_file


def main():
    parser = argparse.ArgumentParser(
        description="Bug Hunting Recon Automation Tool")
    parser.add_argument("-t", "--target", required=True,
                        help="Target domain or IP")
    parser.add_argument("-o", "--output", default="recon_results",
                        help="Output directory for logs")
    args = parser.parse_args()

    log_file = os.path.join(
        LOG_DIR, f"{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    summary = {"target": args.target, "timestamp": datetime.now().isoformat()}

    log_message(f"Starting recon for target: {args.target}", log_file)

    # Step 1: Reconnaissance
    gather_public_data(args.target, log_file, summary)
    check_certificates(args.target, log_file, summary)

    # Step 2: Subdomain Enumeration
    enumerate_subdomains(args.target, log_file, summary)

    # Step 3: Identify Technologies
    identify_technologies(args.target, log_file, summary)

    # Step 4: Vulnerability Scanning
    scan_vulnerabilities(args.target, log_file, summary)

    log_message("Recon completed successfully.", log_file)
    json_file = export_summary_json(summary, args.target)
    log_message(f"Summary JSON exported to: {json_file}", log_file)
    print(f"Recon completed. Logs saved to: {log_file}")
    print(f"Summary JSON saved to: {json_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Process interrupted by user.")
        print("Happy Hacking... Real bugs hide behind deep logic.")
        print("Exiting program. Goodbye!")
        sys.exit(0)
        # Retry the main function after a short delay
        # This allows the script to recover from transient errors
        # and continue running without crashing.
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(5)
        main()
