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

# Main Application Class
class NetworkTrafficApp:
    def __init__(self, root):
        self.root = root
        self.root.title("netWatch - Network Traffic Detection")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f4f4f9")

        # App Logo and Tagline
        #self.logo = tk.PhotoImage(file=r"c:\Users\Khushi Halijole\OneDrive\Pictures\Screenshots\Screenshot 2025-02-22 163943.png")  # Replace with your logo file
        #self.logo_label = tk.Label(root, image=self.logo, bg="#f4f4f9")
        #self.logo_label.pack(pady=20)

        self.tagline = tk.Label(root, text='"Your Network, Your Watch"', font=("Arial", 14), bg="#f4f4f9", fg="#2c3e50")
        self.tagline.pack()

        # Show Login Page by Default
        self.show_login_page()

    # Show Login Page
    def show_login_page(self):
        self.clear_frame()
        self.login_frame = tk.Frame(self.root, bg="#f4f4f9")
        self.login_frame.pack(pady=50)

        tk.Label(self.login_frame, text="Login", font=("Arial", 24), bg="#f4f4f9", fg="#2c3e50").pack(pady=10)

        tk.Label(self.login_frame, text="Email", bg="#f4f4f9", fg="#333").pack()
        self.email_entry = tk.Entry(self.login_frame, width=30)
        self.email_entry.pack(pady=5)

        tk.Label(self.login_frame, text="Password", bg="#f4f4f9", fg="#333").pack()
        self.password_entry = tk.Entry(self.login_frame, width=30, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(self.login_frame, text="Login", command=self.login, bg="#2c3e50", fg="white", width=20).pack(pady=10)
        tk.Button(self.login_frame, text="Sign Up", command=self.show_signup_page, bg="#34495e", fg="white", width=20).pack(pady=5)

    # Show Sign-Up Page
    def show_signup_page(self):
        self.clear_frame()
        self.signup_frame = tk.Frame(self.root, bg="#f4f4f9")
        self.signup_frame.pack(pady=50)

        tk.Label(self.signup_frame, text="Sign Up", font=("Arial", 24), bg="#f4f4f9", fg="#2c3e50").pack(pady=10)

        tk.Label(self.signup_frame, text="Full Name", bg="#f4f4f9", fg="#333").pack()
        self.fullname_entry = tk.Entry(self.signup_frame, width=30)
        self.fullname_entry.pack(pady=5)

        tk.Label(self.signup_frame, text="Email", bg="#f4f4f9", fg="#333").pack()
        self.signup_email_entry = tk.Entry(self.signup_frame, width=30)
        self.signup_email_entry.pack(pady=5)

        tk.Label(self.signup_frame, text="Password", bg="#f4f4f9", fg="#333").pack()
        self.signup_password_entry = tk.Entry(self.signup_frame, width=30, show="*")
        self.signup_password_entry.pack(pady=5)

        tk.Button(self.signup_frame, text="Create Account", command=self.signup, bg="#2c3e50", fg="white", width=20).pack(pady=10)
        tk.Button(self.signup_frame, text="Back to Login", command=self.show_login_page, bg="#34495e", fg="white", width=20).pack(pady=5)

    # Show Dashboard
    def show_dashboard(self):
        self.clear_frame()
        self.dashboard_frame = tk.Frame(self.root, bg="#f4f4f9")
        self.dashboard_frame.pack(pady=20)

        tk.Label(self.dashboard_frame, text="Dashboard", font=("Arial", 24), bg="#f4f4f9", fg="#2c3e50").pack(pady=10)

        # Network Traffic Stats
        self.stats_frame = tk.Frame(self.dashboard_frame, bg="#f4f4f9")
        self.stats_frame.pack(pady=10)

        self.total_traffic_label = tk.Label(self.stats_frame, text="Total Traffic: 0 MB", bg="#f4f4f9", fg="#333")
        self.total_traffic_label.pack()

        self.active_processes_label = tk.Label(self.stats_frame, text="Active Processes: 0", bg="#f4f4f9", fg="#333")
        self.active_processes_label.pack()

        # Start Monitoring
        self.monitor_network_traffic()

        # Profile Button
        tk.Button(self.dashboard_frame, text="Profile", command=self.show_profile_page, bg="#2c3e50", fg="white", width=20).pack(pady=10)

    # Show Profile Page
    def show_profile_page(self):
        self.clear_frame()
        self.profile_frame = tk.Frame(self.root, bg="#f4f4f9")
        self.profile_frame.pack(pady=50)

        tk.Label(self.profile_frame, text="Profile Details", font=("Arial", 24), bg="#f4f4f9", fg="#2c3e50").pack(pady=10)

        tk.Label(self.profile_frame, text="Name: John Doe", bg="#f4f4f9", fg="#333").pack()
        tk.Label(self.profile_frame, text="Email: john.doe@example.com", bg="#f4f4f9", fg="#333").pack()
        tk.Label(self.profile_frame, text="Joined: January 1, 2023", bg="#f4f4f9", fg="#333").pack()

        tk.Button(self.profile_frame, text="Back to Dashboard", command=self.show_dashboard, bg="#34495e", fg="white", width=20).pack(pady=10)

    # Clear Frame
    def clear_frame(self):
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.destroy()

    # Login Function
    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        # Dummy validation
        if email == "user@example.com" and password == "password":
            self.show_dashboard()
        else:
            messagebox.showerror("Error", "Invalid email or password")

    # Sign-Up Function
    def signup(self):
        fullname = self.fullname_entry.get()
        email = self.signup_email_entry.get()
        password = self.signup_password_entry.get()

        # Dummy sign-up logic
        messagebox.showinfo("Success", "Account created successfully!")
        self.show_login_page()

    # Monitor Network Traffic
    def monitor_network_traffic(self):
        def update_traffic():
            while True:
                net_io = psutil.net_io_counters()
                total_traffic = (net_io.bytes_sent + net_io.bytes_recv) / (1024 * 1024)  # Convert to MB
                active_processes = len(psutil.pids())

                self.total_traffic_label.config(text=f"Total Traffic: {total_traffic:.2f} MB")
                self.active_processes_label.config(text=f"Active Processes: {active_processes}")

                time.sleep(2)  # Update every 2 seconds

        # Run in a separate thread
        threading.Thread(target=update_traffic, daemon=True).start()

# Run the Application
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficApp(root)
    root.mainloop()
