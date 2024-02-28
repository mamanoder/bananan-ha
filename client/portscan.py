import threading
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import socket
from communication import PORT

should_stop = False
open_ports = []
threads = []

def RETURNLS(open_ports_list, callback):
    try:
        callback(open_ports_list)
    except:
        pass

def RETURN(open_port):
    try:
        PORT((open_port))
    except:
        pass


def scan_ports(port_start, ip, result_text, open_ports, num, is_GUI):
    for port in range(port_start, port_start+num):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.15)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
            if is_GUI == True:
                try:
                    result_text.insert(tk.END, f"Port {port}\n")
                except Exception as e:
                    print(e)
                except RuntimeError:
                    pass #need to be fixed
            else:
                # sending = threading.Thread(target=RETURN, args=(port,))
                # sending.start()
                RETURN(port)
        sock.close()

def start_scan(ip, program_port, result_text, is_GUI):
    if is_GUI:
        result_text.insert(tk.END, "Scanning ports...\n")
    open_ports = []
    threads = []
    num = 20
    if program_port == None:
        program_port = 999999
    for port in range(1, 65535 - num, num):
        if port > program_port or port+num < program_port:
            scan_thread = Thread(target=scan_ports, args=(port, ip, result_text, open_ports, num, is_GUI))
            threads.append(scan_thread)
        else:
            print(f"Port {port} is$")
            need = program_port - port - 1
            new_port = port + need + 2
            scan_thread = Thread(target=scan_ports, args=(port, ip, result_text, open_ports, need, is_GUI))
            num = num - need - 1
            scan_thread2 = Thread(target=scan_ports, args=(new_port, ip, result_text, open_ports, num, is_GUI))
            threads.append(scan_thread)
            scan_thread2.start()
        scan_thread.start()


    for thread in threads:
        thread.join()

    if is_GUI:
        result_text.insert(tk.END, "Scan completed:\n")
        result_text.insert(tk.END, f"The port list is: {open_ports}\n")

    return True
def on_GUI_scan(ip_entry, result_text):
    is_GUI = True
    on_start_scan(ip_entry, result_text, is_GUI)

def on_start_scan(ip_entry, result_text, is_GUI):
    try:
        ip = ip_entry.get()
    except AttributeError:
        ip = ip_entry
        program_port = None
    scan_thread = Thread(target=start_scan, args=(ip, program_port, result_text, is_GUI))
    scan_thread.start()

# GUI


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Port Scanner")
    root.geometry("500x500")

    # Input fields
    ip_label = tk.Label(root, text="Target IP:")
    ip_label.pack(pady=5)
    ip_entry = tk.Entry(root)
    ip_entry.pack(pady=5)
    scan_button = tk.Button(root, text="Scan Ports", command=lambda: on_GUI_scan(ip_entry, result_text))
    scan_button.pack(pady=10)
    result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=15)
    result_text.pack(pady=10)

    # Result area
    result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=15)
    result_text.pack(pady=10)

    root.mainloop()
