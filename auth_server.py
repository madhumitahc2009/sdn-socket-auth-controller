import json
import os
import socket
import subprocess
import threading

USERS = {
    "alice": "pass123",
    "bob": "password123"
}

# Maps username -> client_ip for active sessions
ACTIVE_SESSIONS = {}

def handle_client(conn, addr):
    client_ip = addr[0]
    try:
        data = conn.recv(1024).decode('utf-8').strip()
        if not data:
            return

        payload = json.loads(data)
        action = payload.get("action", "login")

        # --- 1. Dynamic User Registration ---
        if action == "register":
            reg_u = payload.get("username", "").strip()
            reg_p = payload.get("password", "").strip()
            if not reg_u or not reg_p:
                conn.sendall(b"REG_EMPTY\n")
            elif reg_u in USERS:
                conn.sendall(b"REG_EXISTS\n")
            else:
                USERS[reg_u] = reg_p
                print(f"[AUTH DAEMON] Registered new user: '{reg_u}'")
                conn.sendall(b"REG_SUCCESS\n")
            return

        # --- 2. Dynamic User Deletion / Instant Revocation ---
        if action == "delete":
            del_u = payload.get("username", "").strip()
            if not del_u:
                conn.sendall(b"DEL_EMPTY\n")
            elif del_u not in USERS:
                conn.sendall(b"DEL_NOT_FOUND\n")
            else:
                # Flush switch rules if user has an active session
                if del_u in ACTIVE_SESSIONS:
                    target_ip = ACTIVE_SESSIONS.pop(del_u)
                    print(f"[AUTH DAEMON] User '{del_u}' had active session at {target_ip}. Tearing down flows on s1...")
                    subprocess.run(f"ovs-ofctl -O OpenFlow13 del-flows s1 'tcp,nw_src={target_ip},nw_dst=10.0.0.20,tp_dst=80'", shell=True)
                    subprocess.run(f"ovs-ofctl -O OpenFlow13 del-flows s1 'tcp,nw_src=10.0.0.20,nw_dst={target_ip},tp_src=80'", shell=True)

                del USERS[del_u]
                print(f"[AUTH DAEMON] Deleted user: '{del_u}'")
                conn.sendall(b"DEL_SUCCESS\n")
            return

        # --- 3. User Authentication / Login ---
        username = payload.get("username", "").strip()
        password = payload.get("password", "").strip()

        if username in USERS and USERS[username] == password:
            print(f"[AUTH DAEMON] Authentication SUCCESS for '{username}' ({client_ip})")
            
            ACTIVE_SESSIONS[username] = client_ip

            cmd_fwd = (f"ovs-ofctl -O OpenFlow13 add-flow s1 "
                       f"priority=100,ip,nw_src={client_ip},nw_dst=10.0.0.20,tcp,tp_dst=80,actions=normal")
            subprocess.run(cmd_fwd, shell=True)

            cmd_rev = (f"ovs-ofctl -O OpenFlow13 add-flow s1 "
                       f"priority=100,ip,nw_src=10.0.0.20,nw_dst={client_ip},tcp,tp_src=80,actions=normal")
            subprocess.run(cmd_rev, shell=True)
            conn.sendall(b"AUTH_SUCCESS\n")
        else:
            print(f"[AUTH DAEMON] Authentication FAILED for '{username}' from {client_ip}. Enforcing penalty lockdown...")
            
            # Immediately flush any active rules for this host IP
            subprocess.run(f"ovs-ofctl -O OpenFlow13 del-flows s1 'tcp,nw_src={client_ip},nw_dst=10.0.0.20,tp_dst=80'", shell=True)
            subprocess.run(f"ovs-ofctl -O OpenFlow13 del-flows s1 'tcp,nw_src=10.0.0.20,nw_dst={client_ip},tp_src=80'", shell=True)
            
            # Clear active session mapping
            for user, ip in list(ACTIVE_SESSIONS.items()):
                if ip == client_ip:
                    del ACTIVE_SESSIONS[user]

            conn.sendall(b"AUTH_FAILURE\n")

    except Exception as e:
        print(f"[AUTH DAEMON] Request error: {e}")
        try:
            conn.sendall(b"ERROR\n")
        except Exception:
            pass
    finally:
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 9000))
    server.listen(5)
    print("[AUTH DAEMON] Low-level TCP socket daemon listening on port 9000...")
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    start_server()
