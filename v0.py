import psutil
import time
import csv
import threading
import os
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP
import matplotlib.pyplot as plt
from collections import defaultdict
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Global Variables
protocol_counts = defaultdict(int)
packet_data = []
filtered_data = []

# GUI Setup
root = tk.Tk()
root.title("Live Network Traffic Monitor")
root.geometry("1000x600")

# Packet Log Table
frame = ttk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

tree = ttk.Treeview(frame, columns=("Timestamp", "Source IP", "Destination IP", "Protocol"), show="headings")
tree.heading("Timestamp", text="Timestamp")
tree.heading("Source IP", text="Source IP")
tree.heading("Destination IP", text="Destination IP")
tree.heading("Protocol", text="Protocol")

tree.column("Timestamp", width=150)
tree.column("Source IP", width=200)
tree.column("Destination IP", width=200)
tree.column("Protocol", width=100)

tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
scrollbar.pack(side=tk.RIGHT, fill="y")
tree.configure(yscrollcommand=scrollbar.set)

# Function to log packet data to CSV
def log_packet_data(src_ip, dst_ip, protocol):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    packet_data.append((timestamp, src_ip, dst_ip, protocol))

    # Update GUI Table
    tree.insert("", "end", values=(timestamp, src_ip, dst_ip, protocol))

    # Write to CSV
    with open("packet_log.csv", mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, src_ip, dst_ip, protocol])

# Packet Capture Callback
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"

        log_packet_data(src_ip, dst_ip, protocol)
        protocol_counts[protocol] += 1

# Start Packet Capture
def start_packet_capture():
    print("[Packet Capture] Starting...")
    iface_list = get_if_list()
    print(f"Available Interfaces: {iface_list}")

    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error capturing packets: {e}")

# Update Protocol Graph
def update_protocol_graph():
    while True:
        time.sleep(5)  # Update every 5 seconds
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())

        plt.clf()
        plt.bar(protocols, counts, color=["blue", "red", "green", "purple"])
        plt.xlabel("Protocols")
        plt.ylabel("Packet Count")
        plt.title("Protocol Distribution")

        canvas.draw()

# Display Network Usage
def display_network_usage():
    while True:
        os.system("cls" if os.name == "nt" else "clear")  # Clear the console
        print("=== Network Usage ===")
        print("{:<20} {:<15} {:<15}".format("Process", "Upload (KB/s)", "Download (KB/s)"))
        print("-" * 50)

        process_data = {}

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                net_io = psutil.net_io_counters()
                sent_kb = net_io.bytes_sent / 1024
                received_kb = net_io.bytes_recv / 1024
                process_data[proc.info['name']] = {'Upload': sent_kb, 'Download': received_kb}
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        for proc, data in process_data.items():
            print("{:<20} {:<15.2f} {:<15.2f}".format(proc, data['Upload'], data['Download']))

        time.sleep(1)

# Add Graph for Protocol Distribution
fig = plt.figure(figsize=(5, 3))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

# Search and Filter Packets
def search_packets():
    query = search_entry.get().lower()
    tree.delete(*tree.get_children())  # Clear table

    for row in packet_data:
        if query in str(row).lower():
            tree.insert("", "end", values=row)

# Search Bar
search_frame = ttk.Frame(root)
search_frame.pack(fill=tk.X)

search_label = ttk.Label(search_frame, text="Search:")
search_label.pack(side=tk.LEFT, padx=5)

search_entry = ttk.Entry(search_frame, width=50)
search_entry.pack(side=tk.LEFT, padx=5)

search_button = ttk.Button(search_frame, text="Filter", command=search_packets)
search_button.pack(side=tk.LEFT, padx=5)

# Export to CSV
def export_csv():
    with open("exported_packets.csv", mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol"])
        writer.writerows(packet_data)

export_button = ttk.Button(root, text="Export CSV", command=export_csv)
export_button.pack()

# Start threads
threading.Thread(target=start_packet_capture, daemon=True).start()
threading.Thread(target=update_protocol_graph, daemon=True).start()
threading.Thread(target=display_network_usage, daemon=True).start()

# Run GUI
root.mainloop()
