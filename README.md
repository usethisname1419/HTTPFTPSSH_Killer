# HTTPFTPSSH_Killer

Introducing HFSK – your sophisticated brute-forcing tool tailored for HTTP, SSH and FTP services. Unlike conventional brute-forcing, HFSK emulates the "password spraying" approach by attempting three passwords per user. Once it exhausts the user list, it resumes by cycling through the next set of three passwords. This reduces the chance of lockouts and lost connections. 

Key Features:

1. Target Selection: The tool grants users the flexibility to pick between HTTP(S), FTP and SSH services and choose port number for their attack. 

2. Password Options: Opt between using a predetermined wordlist or generating random passwords on-the-fly. If randomness entices you, HFSK can concoct passwords using `--rand 8 16` for passwords between 8 and 16 or specify any min and max length you desire.

3. Different methods to determine success for HTTP(s) - `--status-code`, `--failure-content-length`, `--success-content-length`, `--failure-pattern`, `--success-pattern`

4. Anonymization: Cover your tracks. With HFSK, you can route your traffic through Tor or select from a personalized list of proxies.

5. Support random user-agents 

6. Detailed Reporting: Stay informed. Post-attack, HFSK provides a concise report detailing the duration of the attack and the number of attempts made.

7. Resume your attack from last known state.

8. Pause function to set when to pause and how long --pause 3 1 [pauses every 3 minutes for 1 minute]

9. Verbosity levels 1 and 2 for detailed messages

10. Force new session creation with --sessions

11. Load CSRF token `--csrf`

12. Add common preffixes/suffixes to password attempts `--suffix` `--prefix`


HFSK is designed to reduce the chance of lockouts 



## Disclaimer

**Brute-forcing against any system without explicit permission is illegal and unethical. Always have proper authorization before conducting any testing. Use this tool responsibly and ethically.**

## Installation

1. Clone this repository:

`git clone https://github.com/usethisname1419/HTTPFTPSSH_Killer.git`

`cd HTTPFTPSSH_Killer`


3. Install the required libraries:

`pip install -r requirements.txt`

4. Install HFSKv6.py

`chmod +x install.sh`

`./install.sh`

You can now call HFSKv6 from command line by typing "HFSK"

## Options

-sv --service

--ip

--tor

-px --proxies

-w --wordlist

-r --rand

-i --iterations

-u --users

--http-post

--failure-content-length

--success-content-length

--failure-pattern

--success-pattern

--status-code

-ra --random-agent

--verbose

--resume

-ps --pause

-ss --sessions

--suffix

--prefix

--csrf

HFSKv7

--fast-mode = Run all interations at same time using threading (experimental)


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

Check HTTP(S) success with content-length, status-codes, response-patterns `--status code`, `--failure/success-conten-length`, `--failure/success-pattern`

Add suffix/prefix to password attempts `--suffix`, `--prefix`

Force sessions `--sessions`

Use CSRF token for HTTP(S) `--csrf` - `--http-post "token=^CSRF^&login=^USER^&pwd=^PASS^"`

Resume your attack from last known state `--resume`(Include the same args as last attack)



## Support

If you found this tool useful, consider supporting its development!

**Ethereum (ETH)**: `0xB139a7f6A2398fd4F50BbaC9970da8BE57E6F539`

**Bitcoin (BTC)**: `bc1qtezfajhysn6dut07m60vtg0s33jy8tqcvjqqzk`

---

Designed and maintained by Derek Johnston.

I hope you find this tool useful and I encourage you to share this tool among friends and colleuges!

Future plans: i plan to make the suffix/prefix try every combo on each word before moving on to the next one. I also plan to create a fast mode where it uses as many threads as there is interations for a faster attack. please support.

