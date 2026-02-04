import socket

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

def main():
    target = input("Enter target IP: ")
    for port in range(1, 1025):
        if scan_port(target, port):
            print(f"Port {port} is open")

if __name__ == "__main__":
    main()
