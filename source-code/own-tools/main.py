import socket
import random
import string
import hashlib
import requests
from urllib.parse import urlparse

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

def port_scan(target):
    open_ports = []
    for port in range(1, 1025):
        if scan_port(target, port):
            open_ports.append(port)
    return open_ports

def vuln_check(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url
    try:
        response = requests.get(url, timeout=5)
        vulns = []
        if "Server" in response.headers:
            vulns.append(f"Server header exposed: {response.headers['Server']}")
        if response.status_code == 200 and "DVWA" in response.text:
            vulns.append("Possible DVWA instance detected")
        return vulns
    except:
        return ["Error checking URL"]

def pass_gen(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def hash_crack(hash_str):
    common_words = ["password", "123456", "qwerty", "admin", "letmein"]
    for word in common_words:
        if hashlib.md5(word.encode()).hexdigest() == hash_str:
            return f"Cracked: {word}"
    return "Hash not cracked (simple dict only)"

def osint_search(query):
    # Simulated OSINT, no real internet
    return f"Simulated OSINT results for '{query}': No real data, educational only."

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: own-tools <subcommand> [args]")
        print("Subcommands: port-scan <target>, vuln-check <url>, pass-gen <length>, hash-crack <hash>, osint-search <query>")
        return
    subcmd = sys.argv[1]
    if subcmd == "port-scan":
        if len(sys.argv) < 3:
            print("Usage: port-scan <target>")
            return
        target = sys.argv[2]
        open_ports = port_scan(target)
        print(f"Open ports on {target}: {open_ports}")
    elif subcmd == "vuln-check":
        if len(sys.argv) < 3:
            print("Usage: vuln-check <url>")
            return
        url = sys.argv[2]
        vulns = vuln_check(url)
        print("Vulnerabilities:")
        for v in vulns:
            print(v)
    elif subcmd == "pass-gen":
        if len(sys.argv) < 3:
            print("Usage: pass-gen <length>")
            return
        length = int(sys.argv[2])
        print("Generated password:", pass_gen(length))
    elif subcmd == "hash-crack":
        if len(sys.argv) < 3:
            print("Usage: hash-crack <hash>")
            return
        hash_str = sys.argv[2]
        print(hash_crack(hash_str))
    elif subcmd == "osint-search":
        if len(sys.argv) < 3:
            print("Usage: osint-search <query>")
            return
        query = ' '.join(sys.argv[2:])
        print(osint_search(query))
    else:
        print("Unknown subcommand")

if __name__ == "__main__":
    main()
