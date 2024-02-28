import psutil
import time
import socket
import requests
import binascii


def get_service_name(port):
    try:
        service_name = socket.getservbyport(port)
        return service_name
    except (socket.error, socket.herror, socket.gaierror, socket.timeout):
        return "N/A"


def get_website_name(ip):
    try:
        # Use a simple GET request to extract the title of an HTML page
        response = requests.get(f"http://{ip}", timeout=5)
        if response.status_code == 200:
            title_start = response.text.find("<title>") + len("<title>")
            title_end = response.text.find("</title>")
            return response.text[title_start:title_end].strip()
    except requests.RequestException:
        pass
    return "N/A"

def inspect_data(data):
    # Check for common file signatures
    file_signatures = {
        "JPEG": "ffd8ffe000104a464946",
        "PNG": "89504e470d0a1a0a",
        "PDF": "25504446",
    }

    for file_type, signature in file_signatures.items():
        if data.startswith(binascii.unhexlify(signature)):
            return f"File type: {file_type}"

    # If no match, assume it's text
    try:
        text_data = data.decode("utf-8")
        return f"Text data: {text_data}"
    except UnicodeDecodeError:
        return "Unknown data format"

def get_connections():
    connections = psutil.net_connections(kind='inet')
    return [(conn.laddr, conn.raddr) for conn in connections if conn.laddr and conn.raddr]

def format_connection_info(local_addr, remote_addr):
    local_ip, local_port = local_addr if local_addr else ("N/A", "N/A")
    remote_ip, remote_port = remote_addr if remote_addr else ("N/A", "N/A")

    if ':' in local_ip:
        local_ip = f"[IPv6] {local_ip}"
    else:
        local_ip = f"[IPv4] {local_ip}"

    if ':' in remote_ip:
        remote_ip = f"[IPv6] {remote_ip}"
    else:
        remote_ip = f"[IPv4] {remote_ip}"

    return local_ip, local_port, remote_ip, remote_port

def monitor_connections():
    previous_connections = set()

    while True:
        current_connections = set(get_connections())
        new_connections = current_connections - previous_connections

        for local_addr, remote_addr in new_connections:
            formatted_info = format_connection_info(local_addr, remote_addr)
            service_name = get_service_name(int(formatted_info[3]))
            website_name = get_website_name(formatted_info[2])

            print("A new connection was made!")
            print(f"Connection information - IP: {formatted_info[2]}, Port: {formatted_info[3]} ({service_name})")
            print(f"Transferring data from computer: {formatted_info[0]}:{formatted_info[1]}")

            if service_name == "http":
                print(f"Website: {website_name}")

            # Capture and inspect the first 50 bytes of data
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
                    s.bind(('localhost', 0))
                    s.connect((formatted_info[2], int(formatted_info[3])))
                    s.send(b'GET / HTTP/1.1\r\n\r\n')
                    data = s.recv(50)
                    print(f"Data content: {inspect_data(data)}")

            except Exception as e:
                print(f"Failed to inspect data: {e}")

            print("")

        previous_connections = current_connections
        time.sleep(1)

if __name__ == "__main__":
    monitor_connections()
