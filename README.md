# HackTIve
Active Threat Intelligence Framework

## Intro & Setup

HackTIve is XXX

To install and setup do:
```
git clone https://github.com/PwnDexter/HackTIve.git
pip3 install -r requirements.txt
python3 HackTIve.py <args>
```

## Roadmap & Ideas

- [x] - Perform WHOIS
    - [ ] - Rewrite in Python3
- [x] - Perform Reverse WHOIS
    - [ ] - Beautify the output
    - [x] - Write out the domains to a file or array
- [x] - Perform DNS
    - [ ] - Rewrite in Python3
- [ ] - Perform sub domain enumeration on identified domains
    - [ ] - Aquatone
    - [ ] - sublister
    - [ ] - other tools?
- [ ] - Write out all domains and sub domains to a file or array and unique them and count them
- [ ] - Perform domain front checking against all identified domains and sub domains
- [ ] - Look into third party api calls such as shodan, pastebin, hunter, wayback machine/url etc. and see if any are of use.
- [x] - Perform Cert transparency query and pull out subdomains i.e., https://crt.sh/?q=%25.nettitude.com
