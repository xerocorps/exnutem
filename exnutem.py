#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import time
import requests
import argparse
import subprocess
import shutil
from colorama import Fore, Style, init
from dotenv import load_dotenv
import logging

# Initialize colorama
init(autoreset=True)

# Initialize logging
logging.basicConfig(level=logging.DEBUG)

# Load environment variables from .env file
load_dotenv()

BASE_URL = "https://api.github.com"

def debug_log(msg: str, debug: bool) -> None:
    """Log the given message if debug is True."""
    if debug:
        logging.debug(msg)

def handle_response(response: requests.Response, debug: bool, authenticated: bool = True) -> bool:
    """Handle the response from an API request."""
    debug_log(f"{Fore.BLUE}[+] Received response with status code: {Fore.GREEN}{response.status_code}{Style.RESET_ALL}", debug)

    if response.status_code == 403:
        print(f"{Fore.RED}[-] Forbidden: Check your token and permissions.{Style.RESET_ALL}")
        return False
    elif response.status_code != 200:
        print(f"{Fore.RED}[-] Error with status code: {Fore.RED}{response.status_code}{Style.RESET_ALL}")
        return False

    rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
    rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

    threshold = 5 if authenticated else 1

    if rate_limit_remaining < threshold:
        reset_time = max(rate_limit_reset - time.time(), 0)
        if reset_time > 180:  # 180 seconds = 3 minutes
            print(f"{Fore.RED}[-] Rate limit reset time exceeds 3 minutes. Stopping further processing.{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}[!] Rate limit reset time is less than 3 minutes. Waiting for {reset_time:.2f} seconds until reset.{Style.RESET_ALL}")
            time.sleep(reset_time)

    return True

def append_to_file(filename: str, data: list) -> None:
    """Append data to a file."""
    with open(filename, "a") as file:
        for item in data:
            file.write(f"{item}\n")

def search_github_repos(query_terms: list, debug: bool = False) -> None:
    token = os.getenv('GITHUB_API_KEY', None)
    authenticated = True

    headers = {'Accept': 'application/vnd.github.v3+json'}

    if token:
        headers['Authorization'] = f'token {token}'
    else:
        print(f"{Fore.YELLOW}[!] GitHub API token not found. Proceeding with unauthenticated search.{Style.RESET_ALL}")
        authenticated = False

    found_repos = []
    new_templates_file = "new_templates.txt"
    existing_repos = set()

    if os.path.exists("nuclei.txt"):
        shutil.copy("nuclei.txt", "nuclei.txt.bak")
        with open("nuclei.txt.bak", "r") as file:
            existing_repos = set(line.strip() for line in file.readlines() if line.strip() and not line.startswith("#"))

    with open(new_templates_file, "r") as file:
        new_templates_repos = set(line.strip() for line in file.readlines() if line.strip() and not line.startswith("#"))

    while True:
        current_terms = query_terms[:5]  # Get first 5 terms
        query_terms = query_terms[5:]  # Remove first 5 terms

        search_url = f"{BASE_URL}/search/repositories"
        search_params = {'q': ' OR '.join(current_terms), 'page': 1}

        debug_log(f"{Fore.BLUE}Searching repositories with terms: {Fore.GREEN}{current_terms}{Style.RESET_ALL}", debug)

        try:
            response = requests.get(search_url, headers=headers, params=search_params)
        except requests.RequestException as e:
            print(f"An error occurred: {e}")
            return

        if not handle_response(response, debug, authenticated):
            return

        data = response.json()

        for repo in data["items"]:
            contents_url = f"{BASE_URL}/repos/{repo['full_name']}/contents"
            try:
                contents_response = requests.get(contents_url, headers=headers)
            except requests.RequestException as e:
                print(f"An error occurred: {e}")
                continue

            if not handle_response(contents_response, debug, authenticated):
                continue

            contents = contents_response.json()
            if any(file['name'].endswith(('.yaml', '.yml')) for file in contents):
                repo_url = repo['html_url']
                if repo_url not in existing_repos and repo_url not in new_templates_repos:
                    print(f"{Fore.GREEN}[+] Found New Nuclei Template Repo: {Fore.MAGENTA}{repo_url}{Style.RESET_ALL}")
                    debug_log(f"{Fore.GREEN}[+] Adding {Fore.MAGENTA}{repo_url}{Style.RESET_ALL} to found repositories", debug)
                    found_repos.append(repo_url)

        if not query_terms:
            break

    print(f"\n{Fore.GREEN}[+] Found {len(found_repos)} new Nuclei Template repositories.{Style.RESET_ALL}")

    if found_repos:
        user_input = input(f"{Fore.BLUE}[*] Do you want to download the found repositories? (y/n): {Style.RESET_ALL}").strip().lower()
        if user_input == 'y':
            append_to_file(new_templates_file, found_repos)
            print(f"{Fore.GREEN}[+] Running getnucleitemplates.py...{Style.RESET_ALL}")
            subprocess.run(["python3", "getnucleitemplates.py", "-f", new_templates_file])

        user_input = input(f"\n{Fore.BLUE}[*] Do you want to add the new found repositories to nuclei.txt? (y/n): {Style.RESET_ALL}").strip().lower()
        if user_input == 'y':
            append_to_file("nuclei.txt", found_repos)
    else:
        print(f"{Fore.LIGHTRED_EX}[-] No new repositories found.{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Enable debug logging", action="store_true")
    args = parser.parse_args()
    search_terms = [
    "nuclei-templates",
    "nuclei-scripts",
    "nuclei-configs",
    "nuclei-vulnerabilities",
    "nuclei-security",
    "nuclei-scans",
    "nuclei-audit",
    "nuclei-assessments",
    "nuclei-checks",
    "nuclei-security-checks",
    "nuclei-web-security",
    "nuclei-web-vulnerabilities",
    "nuclei-web-scans",
    "nuclei-web",
    "nuclei-scanner",
    "nuclei-audit",
    "nuclei-exploit",
    "nuclei-fuzz",
    "nuclei-detection",
    "nuclei-recon",
    "nuclei-injection",
    "nuclei-pentest",
    "nuclei-assessment",
    "nuclei-payload",
    "nuclei-scan",
    "nuclei-attack",
    "nuclei-verification",
    "nuclei-penetration",
    "nuclei-testing",
    "nuclei-instrumentation",
    "nuclei-hunter",
    "nuclei-analysis",
    "nuclei-research",
    "nuclei-discovery",
    "nuclei-assurance",
    "nuclei-investigation",
    "nuclei-verification",
    "nuclei-forensics"
    ]
    search_github_repos(search_terms, debug=args.debug)
