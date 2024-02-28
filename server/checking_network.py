import re
import threading
import base64
import quopri
import binascii
from urllib.parse import unquote
from open_server import *
import pickle
from open_server import *
import server_GUI


filters = [
    "username=.*",
    "password=.*",
    "ssid=.*",
    "account=.*",
    "routing=.*",
    "ssn=.*",
    "username.*",
    "password.*"
]






def starting(traffic):
    parts = traffic.split(">")
    if len(parts) == 2:
        ip, tcp_info = map(str.strip, parts)
        tcp, decoded_data = tcp_info.split(":")
        check_traffic = threading.Thread(target=check, args=(ip, tcp, decoded_data))
        check_traffic.start()
        check_traffic.join()



def check(data, ip, port):
    for f in filters:
        match = re.search(f, data)
        if match:
            print(f"[!] ALERT: Data match found in packet to {ip}:{port}: {data}. Triggered filter: {f}, Matched content: {match.group()}")
            save_stolen_content(match.group())
            return True
    print(f"[+] No sensitive data match found in packet to {ip}:{port}: {data}")
    return False

def save_stolen_content(stolen_content):
    # Modify this function to save the stolen content as per your requirements
    # For example, you can print it or store it in a variable, file, or database
    print(f"Stolen content: {stolen_content}")


def handle_packet_summary(packet_summary):
    source_ip = packet_summary.get("source_ip")
    destination_ip = packet_summary.get("destination_ip")
    source_port = packet_summary.get("source_port")
    destination_port = packet_summary.get("destination_port")
    protocol = packet_summary.get("protocol")
    payload = packet_summary.get("payload")
    data = packet_summary.get("data")

    print(f"Received packet summary:")
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print(f"Source Port: {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Protocol: {protocol}")
    print(f"Payload: {payload}")
    print(f"data: {data}")

    try:
        check(data, destination_ip, destination_port)
    except Exception as e:
        print(f"Error trying to search in the data: {e}")

    try:
        decoded_data = decode_hex(data)
        start_checking(decoded_data, destination_ip, destination_port)
    except Exception as e:
        print(f"Error decoding data: {e}")


def start_checking(data, destination_ip, destination_port):
    decode_methods = [decode_utf8, decode_ascii, decode_base64, decode_url, decode_quoted_printable]

    # try:
    #     if run_filters(data):
    #         print(f"[!] ALERT: Data match found in packet to {destination_ip}:{destination_port}: {data}")
    # except Exception as e:
    #     print(f"Error without decoding: {e}")

    for method in decode_methods:
        try:
            decoded_data = method(data)
            check(decoded_data, destination_ip, destination_port)
        except Exception as e:
            print(f"Error decoding data using {method.__name__}: {e}")

    print(f"Good for now")


def run_filters(decoded_data):
    decoded_data_str = decoded_data.decode('utf-8', 'ignore') if isinstance(decoded_data, bytes) else decoded_data
    print(f"Decoded Data: {decoded_data_str}")

    for f in filters:
        if re.search(f, decoded_data_str):
            print(f"Filter Matched: {f}")
            return True
    return False


# Your decode functions remain the same
# def decode_pass(raw_data):
#     if isinstance(raw_data, bytes):
#         decoded_data = raw_data.decode('utf-8', 'ignore')
#         print(f"print 1 {decoded_data}")
#         return decoded_data
#     return raw_data


def decode_utf8(raw_data):
    if isinstance(raw_data, bytes):
        try:
            decoded_data = raw_data.decode('utf-8', 'ignore')
            print(f"print 2 {decoded_data}")
            return decoded_data
        except UnicodeDecodeError:
            pass
    return raw_data


def decode_ascii(raw_data):
    if isinstance(raw_data, bytes):
        try:
            decoded_data = raw_data.decode('ascii', 'ignore')
            print(f"print 3 {decoded_data}")
            return decoded_data
        except UnicodeDecodeError:
            pass
    return raw_data


def decode_base64(data):
    if isinstance(data, bytes):
        missing_padding = len(data) % 4
        if missing_padding:
            data += b'=' * (4 - missing_padding)
        try:
            decoded_data = base64.b64decode(data).decode('utf-8', 'ignore')
            print(f"print 4 {decoded_data}")
            return decoded_data
        except UnicodeDecodeError:
            print("print 5 Error decoding base64 data")
            pass
    return data


def decode_hex(data):
    try:
        if isinstance(data, bytes):
            return binascii.unhexlify(data)
        else:
            # If data is already a string, no need to decode hex
            return data
    except binascii.Error:
        print(f"Error decoding hex data")
        return data



def decode_url(data):
    if isinstance(data, str):
        try:
            decoded_data = unquote(data)
            print(f"print 7 {decoded_data}")
            return decoded_data
        except UnicodeDecodeError:
            print("print 8 Error decoding URL data")
            pass
    return data


def decode_quoted_printable(data):
    if isinstance(data, bytes):
        try:
            decoded_data = quopri.decodestring(data).decode('utf-8', 'ignore')
            print(f"print 9 {decoded_data}")
            return decoded_data
        except UnicodeDecodeError:
            print(f" print 10 Error decoding quoted-printable data")
            pass
    return data



def return_block(ip, port, stolen_data):
    data = {"type": "block", "ip": ip, "port": port, "data": stolen_data}
    client_sockets.send(pickle.dumps(data))

if __name__ == "__main__":
    # Example usage:
    traffic_summary = {
        "source_ip": "192.168.1.1",
        "destination_ip": "192.168.1.2",
        "source_port": 12345,
        "destination_port": 80,
        "protocol": "TCP",
        "payload": "some_payload",
        "data": b'\x17\x03\x03\x001\x811\xeb\xcc\x86\xc0\xca\xff\x93-\xa5\xf5\xffqON\xc89\x7fS\xeb\xaa\xe5\xb8?\xe2\x03(Y\xea\xb8{v\xbd\xe0\xc89Z\x98\xfbH\x8d4\x16<\x13\xec7\xd7'
    }

    handle_packet_summary(traffic_summary)