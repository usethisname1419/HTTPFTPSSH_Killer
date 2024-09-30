# HTTPFTPSSH_Killer

Introducing HFSK – your sophisticated brute-forcing tool tailored for HTTP, SSH and FTP services. Unlike conventional brute-forcing, HFSK emulates the "password spraying" approach by attempting three passwords per user. Once it exhausts the user list, it resumes by cycling through the next set of three passwords. This reduces the chance of lockouts and lost connections. 

Key Features:

1. Target Selection: The tool grants users the flexibility to pick between HTTP(S), FTP and SSH services and choose port number for their attack. 

2. Password Options: Opt between using a predetermined wordlist or generating random passwords on-the-fly. If randomness entices you, HFSK can concoct passwords using `--rand 8 16` for passwords between 8 and 16 or specify any min and max length you desire.

3. Anonymization: Cover your tracks. With HFSK, you can route your traffic through Tor or select from a personalized list of proxies.

4. Detailed Reporting: Stay informed. Post-attack, HFSK provides a concise report detailing the duration of the attack and the number of attempts made.

5. Resume your attack from last known state.



## Disclaimer

**Brute-forcing against any system without explicit permission is illegal and unethical. Always have proper authorization before conducting any testing. Use this tool responsibly and ethically.**

## Installation

1. Clone this repository:

`git clone https://github.com/usethisname1419/HTTPFTPSSH_Killer.git`

`cd HTTPFTPSSH_Killer`


3. Install the required libraries:

`pip install -r requirements.txt`

4. Install HFSKv3.py

`chmod +x install.sh`

`./install.sh`

You can now call HFSKv3 from command line by typing "HFSK"

## Options

--service

--ip

--tor

--proxies

-w --wordlist

-r --rand

-i --iterations

-u --users

--http-post

--failure-content-length

--success-content-length

--failure-pattern

--success-pattern

--random-agent

--verbose

--resume

## Usage

`HFSK --service [ftp/ssh/http][Port} -w [path_to_wordlist] --users [path_to_user_list] --ip [target_ip_address]`

HTTP-POST-FORM ATTACK: 

```HFSK --service http -w --ip [url/(endpoint)] http-post [pass=^PASS^S&users=^USERS^] failure/success-content-length [int] success/failure-pattern [str]```


Example:
`HFSK --service ssh 2222 -w /usr/share/wordlists/rockyou.txt --users users.txt --ip 172.16.1.83 --tor`

Supports services on any port. `--service http 8080`

Supports single user `-u` and user list `--users`

To use random passwords use the flag `-r` or `--rand` Enter min length and max length of random passwords ` -r 6 8` for passwords between 6 and 8 chars

You can load proxies from a list using the `--proxies` flag. 

You can also use the `--tor` flag to route your requests through Tor.

You can change the number of iterations for each attack block with the flag `-i` or `--iter` for number of tries per user name.

Http/Https attack supports random user-agents `--random-agent`

Resume your attack from last known state `--resume`



## Support

If you found this tool useful, consider supporting its development!

**Ethereum (ETH)**: `0xB139a7f6A2398fd4F50BbaC9970da8BE57E6F539`

**Bitcoin (BTC)**: `bc1qtezfajhysn6dut07m60vtg0s33jy8tqcvjqqzk`

---

Designed and maintained by Derek Johnston.

I hope you find this tool useful and I encourage you to share this tool among friends and colleuges!

