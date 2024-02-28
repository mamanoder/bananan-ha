import socket

def scan_ports(target_ip, start_port=1, end_port=1024):
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)

        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    return open_ports

# Example usage:
target_ip = "192.168.56.1"
start_port = 1
end_port = 1024

result = scan_ports(target_ip, start_port, end_port)
print(f"Open ports on {target_ip}: {result}")
