import json
import os
import socket
import subprocess
import tkinter as tk
from tkinter import messagebox, ttk
import urllib.request

AUTH_IP = "10.0.0.10"
AUTH_PORT = 9000
TARGET_URL = "http://10.0.0.20:80"

def get_local_ip():
    """Detect local namespace IP dynamically."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((AUTH_IP, AUTH_PORT))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "10.0.0.1"

class MultiHostZeroTrustGUI:
    def __init__(self, root):
        self.root = root
        self.my_ip = get_local_ip()
        self.hostname = "h1" if self.my_ip == "10.0.0.1" else ("h2" if self.my_ip == "10.0.0.2" else self.my_ip)
        
        self.root.title(f"Zero-Trust SDN Gateway Client — {self.hostname} ({self.my_ip})")
        self.root.geometry("690x790")
        self.root.configure(bg="#0b1329")

        self.total_attempts = 0

        # Header
        tk.Label(root, text=f"SDN Identity Gateway — Client Node: {self.hostname}", font=("Arial", 14, "bold"), fg="#38bdf8", bg="#0b1329").pack(pady=(10, 2))
        tk.Label(root, text=f"Local Interface: {self.my_ip} | Dynamic L4 Policy Control", font=("Arial", 9), fg="#94a3b8", bg="#0b1329").pack(pady=(0, 10))

        # --- 1. USER REGISTRATION / PROVISIONING CARD ---
        reg_card = tk.LabelFrame(root, text=" Dynamic User Provisioning & Deletion ", font=("Arial", 10, "bold"), fg="#38bdf8", bg="#1e293b", bd=1, padx=10, pady=6)
        reg_card.pack(fill="x", padx=15, pady=4)

        tk.Label(reg_card, text="Username:", font=("Arial", 9), fg="#f8fafc", bg="#1e293b").grid(row=0, column=0, sticky="w", pady=2)
        self.reg_user_entry = tk.Entry(reg_card, font=("Arial", 9), width=13)
        self.reg_user_entry.grid(row=0, column=1, pady=2, padx=4)

        tk.Label(reg_card, text="Password:", font=("Arial", 9), fg="#f8fafc", bg="#1e293b").grid(row=0, column=2, sticky="w", padx=(6, 0), pady=2)
        self.reg_pass_entry = tk.Entry(reg_card, show="*", font=("Arial", 9), width=13)
        self.reg_pass_entry.grid(row=0, column=3, pady=2, padx=4)

        self.btn_reg = tk.Button(reg_card, text="Register", font=("Arial", 9, "bold"), bg="#059669", fg="white", command=self.register_user)
        self.btn_reg.grid(row=0, column=4, padx=(6, 2), pady=2)

        self.btn_del = tk.Button(reg_card, text="Delete", font=("Arial", 9, "bold"), bg="#b91c1c", fg="white", command=self.delete_user)
        self.btn_del.grid(row=0, column=5, padx=2, pady=2)

        # --- 2. AUTHENTICATION / LOGIN CARD ---
        cred_card = tk.LabelFrame(root, text=" Client Authentication Portal ", font=("Arial", 10, "bold"), fg="#38bdf8", bg="#1e293b", bd=1, padx=10, pady=8)
        cred_card.pack(fill="x", padx=15, pady=4)

        tk.Label(cred_card, text="Username:", font=("Arial", 9), fg="#f8fafc", bg="#1e293b").grid(row=0, column=0, sticky="w", pady=2)
        self.user_entry = tk.Entry(cred_card, font=("Arial", 9), width=18)
        self.user_entry.grid(row=0, column=1, pady=2, padx=5)

        tk.Label(cred_card, text="Password:", font=("Arial", 9), fg="#f8fafc", bg="#1e293b").grid(row=0, column=2, sticky="w", padx=(10, 0), pady=2)
        self.pass_entry = tk.Entry(cred_card, show="*", font=("Arial", 9), width=18)
        self.pass_entry.grid(row=0, column=3, pady=2, padx=5)

        # Action Buttons
        btn_frame = tk.Frame(root, bg="#0b1329")
        btn_frame.pack(fill="x", padx=15, pady=6)

        self.btn_login = tk.Button(btn_frame, text=f"1. Authenticate ({self.hostname})", font=("Arial", 9, "bold"), bg="#0284c7", fg="white", command=self.authenticate)
        self.btn_login.pack(side="left", expand=True, fill="x", padx=2)

        self.btn_curl = tk.Button(btn_frame, text="2. Test Target Access", font=("Arial", 9, "bold"), bg="#334155", fg="white", command=self.test_target)
        self.btn_curl.pack(side="left", expand=True, fill="x", padx=2)

        self.btn_revoke = tk.Button(btn_frame, text=f"3. Revoke ({self.hostname})", font=("Arial", 9, "bold"), bg="#dc2626", fg="white", command=self.revoke_session)
        self.btn_revoke.pack(side="left", expand=True, fill="x", padx=2)

        # --- 3. STATUS NOTIFICATION BANNER ---
        self.status_bar = tk.Label(root, text=f"STATUS: BLOCKED — Default drop rule active on switch s1 for {self.my_ip}", font=("Arial", 9, "bold"), bg="#7f1d1d", fg="#f87171", pady=6)
        self.status_bar.pack(fill="x", padx=15, pady=4)

        # --- 4. LIVE TELEMETRY COUNTERS CARD ---
        stats_card = tk.LabelFrame(root, text=" Network-Wide SDN Telemetry ", font=("Arial", 10, "bold"), fg="#38bdf8", bg="#1e293b", bd=1, padx=10, pady=8)
        stats_card.pack(fill="x", padx=15, pady=4)

        self.lbl_reqs = tk.Label(stats_card, text=f"Local Auth Attempts ({self.hostname}): 0", font=("Arial", 9, "bold"), fg="#f8fafc", bg="#1e293b")
        self.lbl_reqs.pack(anchor="w", pady=1)

        self.lbl_sessions = tk.Label(stats_card, text="Active Unlocked Hosts: 0", font=("Arial", 9, "bold"), fg="#38bdf8", bg="#1e293b")
        self.lbl_sessions.pack(anchor="w", pady=1)

        self.lbl_whitelist = tk.Label(stats_card, text="Whitelisted IP List: None", font=("Arial", 9, "bold"), fg="#94a3b8", bg="#1e293b")
        self.lbl_whitelist.pack(anchor="w", pady=1)

        # --- 5. TOPOLOGY & ENDPOINTS TABLE ---
        topo_card = tk.LabelFrame(root, text=" Active Topology & Endpoints (Mininet Network) ", font=("Arial", 10, "bold"), fg="#38bdf8", bg="#1e293b", bd=1, padx=8, pady=8)
        topo_card.pack(fill="both", expand=True, padx=15, pady=(4, 15))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#0f172a", foreground="#f8fafc", fieldbackground="#0f172a", rowheight=24, font=("Arial", 8))
        style.configure("Treeview.Heading", background="#1e293b", foreground="#38bdf8", font=("Arial", 8, "bold"))
        style.map("Treeview", background=[('selected', '#1e293b')])

        cols = ("Entity", "Role", "IP Address", "Port / Protocol", "SDN Access State")
        self.tree = ttk.Treeview(topo_card, columns=cols, show="headings", height=5)
        
        for col, width in zip(cols, (95, 95, 85, 120, 160)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")

        self.tree.tag_configure("online", foreground="#4ade80")
        self.tree.tag_configure("blocked", foreground="#f87171")
        self.tree.tag_configure("unlocked", foreground="#4ade80")
        self.tree.pack(fill="both", expand=True)

        self.poll_switch_state()

    def get_unlocked_ips_from_ovs(self):
        """Scans switch flow table specifically for outbound authenticated client rules."""
        unlocked = set()
        try:
            output = subprocess.check_output("ovs-ofctl -O OpenFlow13 dump-flows s1", shell=True).decode()
            for line in output.splitlines():
                if "priority=100" in line and "nw_dst=10.0.0.20" in line and "nw_src=" in line:
                    parts = line.split("nw_src=")[1].split(",")[0].strip()
                    if parts in ["10.0.0.1", "10.0.0.2"]:
                        unlocked.add(parts)
        except Exception:
            pass
        return list(unlocked)

    def poll_switch_state(self):
        unlocked_ips = self.get_unlocked_ips_from_ovs()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.tree.insert("", "end", values=("Auth Daemon", "Server Daemon", "10.0.0.10", "9000 (TCP Socket)", "ONLINE"), tags=("online",))
        self.tree.insert("", "end", values=("Target Server", "Server Daemon", "10.0.0.20", "80 (HTTP)", "ONLINE"), tags=("online",))

        # Host h1 entry
        h1_state = "UNLOCKED (Priority 100)" if "10.0.0.1" in unlocked_ips else "BLOCKED (Default Drop)"
        self.tree.insert("", "end", values=("Host h1", "Client Namespace", "10.0.0.1", "Dynamic Ephemeral", h1_state), tags=("unlocked" if "UNLOCKED" in h1_state else "blocked",))

        # Host h2 entry
        h2_state = "UNLOCKED (Priority 100)" if "10.0.0.2" in unlocked_ips else "BLOCKED (Default Drop)"
        self.tree.insert("", "end", values=("Host h2", "Client Namespace", "10.0.0.2", "Dynamic Ephemeral", h2_state), tags=("unlocked" if "UNLOCKED" in h2_state else "blocked",))

        # Telemetry updates
        self.lbl_sessions.config(text=f"Active Unlocked Hosts: {len(unlocked_ips)}")
        wl_str = ", ".join(unlocked_ips) if unlocked_ips else "None"
        self.lbl_whitelist.config(text=f"Whitelisted IP List: {wl_str}", fg="#4ade80" if unlocked_ips else "#94a3b8")

        # Auto-poll every 2 seconds
        self.root.after(2000, self.poll_switch_state)

    def register_user(self):
        new_u = self.reg_user_entry.get().strip()
        new_p = self.reg_pass_entry.get().strip()

        if not new_u or not new_p:
            messagebox.showwarning("Incomplete Data", "Please specify both username and password.")
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((AUTH_IP, AUTH_PORT))
            payload = json.dumps({"action": "register", "username": new_u, "password": new_p})
            s.sendall(payload.encode("utf-8"))
            resp = s.recv(1024).decode("utf-8").strip()
            s.close()

            if resp == "REG_SUCCESS":
                messagebox.showinfo("Success", f"User '{new_u}' registered successfully! You can now log in.")
                self.reg_user_entry.delete(0, tk.END)
                self.reg_pass_entry.delete(0, tk.END)
            elif resp == "REG_EXISTS":
                messagebox.showerror("Error", f"Username '{new_u}' already exists.")
            else:
                messagebox.showerror("Failed", f"Registration refused by auth daemon: {resp}")
        except Exception as e:
            messagebox.showerror("Socket Error", f"Unable to reach auth daemon: {e}")

    def delete_user(self):
        del_u = self.reg_user_entry.get().strip()

        if not del_u:
            messagebox.showwarning("Missing Username", "Please enter the username to delete in the 'Username' field.")
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((AUTH_IP, AUTH_PORT))
            payload = json.dumps({"action": "delete", "username": del_u})
            s.sendall(payload.encode("utf-8"))
            resp = s.recv(1024).decode("utf-8").strip()
            s.close()

            if resp == "DEL_SUCCESS":
                messagebox.showinfo("Success", f"User '{del_u}' deleted from controller database!")
                self.reg_user_entry.delete(0, tk.END)
                self.reg_pass_entry.delete(0, tk.END)
            elif resp == "DEL_NOT_FOUND":
                messagebox.showerror("Error", f"User '{del_u}' does not exist in controller database.")
            else:
                messagebox.showerror("Failed", f"Deletion refused: {resp}")
        except Exception as e:
            messagebox.showerror("Socket Error", f"Unable to reach auth daemon: {e}")

    def authenticate(self):
        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Missing Credentials", "Please enter both username and password.")
            return

        self.total_attempts += 1
        self.lbl_reqs.config(text=f"Local Auth Attempts ({self.hostname}): {self.total_attempts}")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((AUTH_IP, AUTH_PORT))
            payload = json.dumps({"action": "login", "username": username, "password": password})
            s.sendall(payload.encode("utf-8"))
            resp = s.recv(1024).decode("utf-8").strip()
            s.close()

            if resp == "AUTH_SUCCESS":
                self.status_bar.config(text=f"STATUS: AUTH_SUCCESS — OpenFlow rules injected on s1 for {self.my_ip}", bg="#14532d", fg="#4ade80")
            else:
                self.status_bar.config(text="STATUS: AUTH_FAILURE — Invalid Credentials. Drop rule remains active", bg="#7f1d1d", fg="#f87171")
        except Exception as e:
            self.status_bar.config(text=f"STATUS: ERROR — {e}", bg="#7f1d1d", fg="#f87171")

        self.poll_switch_state()

    def test_target(self):
        try:
            req = urllib.request.Request(TARGET_URL)
            with urllib.request.urlopen(req, timeout=1.5) as response:
                if response.status == 200:
                    messagebox.showinfo("Access Granted", f"200 OK: {self.hostname} ({self.my_ip}) connected to Target Server successfully!")
        except Exception:
            messagebox.showerror("Access Blocked", f"Packet Dropped: Target unreachable from {self.hostname} ({self.my_ip}). Zero-Trust drop rule active.")

    def revoke_session(self):
        # Precise, host-specific flow removal
        os.system(f"ovs-ofctl -O OpenFlow13 del-flows s1 'tcp,nw_src={self.my_ip},nw_dst=10.0.0.20,tp_dst=80'")
        os.system(f"ovs-ofctl -O OpenFlow13 del-flows s1 'tcp,nw_src=10.0.0.20,nw_dst={self.my_ip},tp_src=80'")
        self.status_bar.config(text=f"STATUS: REVOKED — Flushed rules for {self.my_ip}. Node is blocked", bg="#7f1d1d", fg="#f87171")
        self.poll_switch_state()

if __name__ == "__main__":
    app_root = tk.Tk()
    gui = MultiHostZeroTrustGUI(app_root)
    app_root.mainloop()
