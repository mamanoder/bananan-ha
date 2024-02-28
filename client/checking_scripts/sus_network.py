import tkinter as tk
import psutil
from tkinter import messagebox
from threading import Thread
import time

class NetworkMonitor:
    def __init__(self, target_ip, target_port, threshold):
        self.target_ip = target_ip
        self.target_port = target_port
        self.threshold = threshold
        self.running = False

        self.root = tk.Tk()
        self.root.title("Network Traffic Monitor")

        self.start_button = tk.Button(self.root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self.root, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        self.running = False
        self.root.destroy()

    def start_monitoring(self):
        self.running = True
        monitoring_thread = Thread(target=self.monitor_traffic)
        monitoring_thread.start()

    def stop_monitoring(self):
        self.running = False

    def monitor_traffic(self):
        while self.running:
            try:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.raddr and conn.raddr.ip == self.target_ip and conn.raddr.port == self.target_port:
                        if conn.sent > self.threshold:
                            self.show_alert(conn.sent)
            except Exception as e:
                print(f"Error monitoring traffic: {e}")

            time.sleep(1)

    def show_alert(self, sent_amount):
        alert_message = f"Unusual amount of traffic sent to {self.target_ip}:{self.target_port}\nSent amount: {sent_amount} bytes"
        messagebox.showwarning("Traffic Alert", alert_message)


if __name__ == "__main__":
    # Replace these values with the IP, port, and threshold you want to monitor
    target_ip = "127.0.0.1"
    target_port = 80
    threshold = 1024 * 1024  # 1 MB threshold

    monitor = NetworkMonitor(target_ip, target_port, threshold)
    monitor.root.mainloop()
