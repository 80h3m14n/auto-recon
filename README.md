An automated Script to perform a reconnaissance on a website for bug hunting purposes.

The tool utilizes popular open-source tools like Amass, nmap, ffuf, gobuster etc.


--

# Step 1: Reconnaissance

Gather information about the target domains and sub-domains. Look for email addresses, sub-domains, and other relevant information.

## Public data 

- https://osintframework.com/
- https://www.exploit-db.com/
- https://pastebin.com/
- https://web.archive.org/


 ## Certificate check 

An SSL certificate subject alternative field lets certificate owners specify additional host names that use the same certificate

- https://crt.sh

- https://censys.io


## Acquisitions

- https://crunchbase.com


 ## Google-Fu
- Copyright text
- Terms of service text
- Privacy policy text

 
 ## Web Spidering/Crawling 

Is a process used to identify all pages on a site

- https://shodan.io
- SpiderFoot
- theHarvester
- Recon-ng

## Registry Data Access Protocol
 (RDAP)
- https://whois.kenic.or.ke
- https://arin.net/resources/registry/whois/rdap


## S3 Buckets

S3 buckets can contain hidden endpoints, logs, credentials, user information, source code, and other useful information.

- https://buckets.grayhatwarfare.com/
- https://github.com/nahamsec/lazys3/
- https://github.com/eth0izzle/bucket-stream/


```bash
pip install awscli
aws s3 ls s3://BUCKET_NAME/
aws s3 cp s3://BUCKET_NAME/FILE_NAME/path/to/local/directory
```

# Step 2: Identify Technologies.

Identify the technologies used by the website (e.g., CMS, frameworks, libraries).

## Advertisement/Analytics relationships

- https://builtwith.com
- https://publicwww.com
- https://stackshare.io/
- https://sitereport.netcraft.com/
- https://www.wappalyzer.com
- whatweb


## Append Phpmyadmin on url
- https://example.com/phpmyadmin



# Step 3: Enumeration

Enumerating the target allows the tester to identify likely areas of weakness.

Identify possible entry and injection points through request and response analysis.

Base tools
- Burpsuite
- OWASP ZAP
- Fiddler tools: https://www.telerik.com/fiddler 



## Sub-domain Enumeration

Each subdomain represents a new angle for attacking the network.
The best way to enumerate subdomains is to use automation.

📌Examine 403 pages carefully to see if you can bypass the protection to access the content.

Tools
- Amass
- https://chaos.projectdiscovery.io/#/
- httprobe
- MassDNS
- Subfinder
- Sublist3r
- https://shodan.io
- https://securitytrails.com
- theHarvester 

Wordlists
- rockyou
- seclist

### 1. Linked & JS discovery 
- Burp suite pro
- Gospider 
- hakrawler
- subdomainizer
- https://retirejs.github.io/retire.js/


```
gobuster dns -d example.com -w wordlist.txt
```

### 2. Sub-domain scraping 
This exposes databases of URLs or domains.

- Google dorks 
- Amass
- Subfinder
- Shosubgo

Examples of google dorks
- site: example.com
- inurl: example.com
- intitle: example.com
- *.example.com
- site:docs.google.com/spreadsheets "target domain"
- site:groups.google.com "target domain"



### 3. Subdomain brute-force 
Guessing for live subdomains

- Dirsearch
- Gobuster
- massDNS
- shuffle DNS
- https://assetnote.io
- altDNS
- puredns
- dirsearch 
- DirBuster 
- bfac 

```
amass enum -brute -d example.com -src
```

### 4. Favicon hash
- favihash

### 5. Copyright/ unique string 
- Google
- https://shodan.io


Search: http.html:"Copyright string"

### 6. Services enumeration
Since services often run on default ports, a good way to find them is by port-scanningthe machine with either active or passive scanning.

- Massscan
- Nmap
- Shodan

```
nmap <ip adddress> 
```


## Directory and File Enumeration

Identify hidden directories and files. 
This can reveal sensitive information or hidden functionality.
The goal is to discover information disclosure vulnerabilities, such as sensitive data exposure.

📗Use forced browsing to automate the process instead of manually doing it.

Forced browsing Tools
- Gobuster
- Feroxbuster
- Dirb
- Dirsearch


## Autonomous System Number 
ASN enumeration 

ASN Tools
- Metabigor
- ASNLookup: asnlookup.com
- Hurricane Electric internet services:  bgp.he.net
- Africa: afrinic.net
- North America: arin.net
- Asia:  apnic.net
- Latin America: lacnic.net
- Europe: ripe.net
- bbot

```
bbot -t example.com -f subdomain-enum
```

## DNS Recon
Find & lookup dns records
(A, AAA, MX, TXT, CNAME)

- https://dnsdumpster.com/



## Reverse DNS
- dnsrecon

$dnsrecon -r <DNS range>


## Reverse Whois (loop)

Whois and reverse whois searches for the registrant and owner information of each known domain.

Tools

- https://reversewhois.io

- https://viewdns.info/reversewhois/

- https://whoxy.com

- DOMLink(requires whoxy API key)

```
amass intel -d example.com -whois

whois example.com
```

## IP Addresses
Another way of discovering your target’s top-level domains is to locateIP addresses

```
netdiscover example.com
whois <IP_address>
```

# Step 4: Vulnerability Scanning

Automated Scanning 
Look for open ports, services, and known vulnerabilities.

Scanning tools
- Nmap
- Nessus 
- OpenVAS

## HTTP response analysis
- Content Security Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options. 

- https://securityheaders.com


Safe scanning methods 

```
nmap -A -F -T3 10.10.10.203 -v

ffuf -w wordlist.txt -u https://test.com/ -p 123
```

# Discalaimer
This is a basic tool that I create while learning about automation, it may not be that effective but just works to some extend



