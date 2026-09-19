#!/usr/bin/env python3
"""
All-in-One WAN Relay Server (GUI) — FIXED & COMPLETE
Python 3.8+ — Standard library only

FIXES:
  - status_lbl AttributeError (label now stored)
  - send_file() completed (chunked streaming)
  - LIST_NODES -> NODES_LIST handler added (roster now works)
  - Frame size limit (10 MB) against flooding
  - Clean start/stop/start cycles, accept-loop error logging
"""

import base64
import hashlib
import hmac
import json
import os
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import urllib.request

CHUNK_SIZE = 64 * 1024
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_LINE = 10 * 1024 * 1024          # 10 MB per JSON frame
AUTH_FILE = "server_auth.json"

PUBLIC_IP_APIS = [
    "https://api4.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ipv4.icanhazip.com",
]


def ts():
    return time.strftime("%H:%M:%S")


def pack(msg: dict) -> bytes:
    return (json.dumps(msg) + "\n").encode("utf-8")


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


def load_or_create_auth() -> dict:
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    salt = os.urandom(16).hex()
    store = {"users": {"admin": {"salt": salt,
                                 "hash": hash_password("changeme", salt)}}}
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    return store


def verify_login(store: dict, username: str, password: str) -> bool:
    user = store.get("users", {}).get(username)
    if not user:
        hmac.compare_digest(hash_password(password, "x" * 32), "0" * 64)
        return False
    return hmac.compare_digest(hash_password(password, user["salt"]), user["hash"])


def fetch_public_ip(timeout=5):
    for url in PUBLIC_IP_APIS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ip = r.read().decode("utf-8").strip()
                if ip and valid_ipv4(ip):
                    return ip
        except Exception:
            continue
    return None


# ---------------------------------------------------------------- login dialog
class LoginDialog(tk.Toplevel):
    def __init__(self, root, store):
        super().__init__(root)
        self.store = store
        self.ok = False
        self.attempts = 0
        self.title("Server Login")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="All-in-One Relay Server",
                  font=("Consolas", 12, "bold")).pack(pady=(0, 6))
        ttk.Label(frm, text="Authentication required").pack(pady=(0, 10))

        row1 = ttk.Frame(frm)
        row1.pack(fill="x", pady=3)
        ttk.Label(row1, text="Username:", width=10, anchor="e").pack(side="left")
        self.user_var = tk.StringVar(value="admin")
        ttk.Entry(row1, textvariable=self.user_var, width=22).pack(side="left", padx=4)

        row2 = ttk.Frame(frm)
        row2.pack(fill="x", pady=3)
        ttk.Label(row2, text="Password:", width=10, anchor="e").pack(side="left")
        self.pass_var = tk.StringVar()
        pe = ttk.Entry(row2, textvariable=self.pass_var, width=22, show="•")
        pe.pack(side="left", padx=4)

        self.err_var = tk.StringVar(value="")
        ttk.Label(frm, textvariable=self.err_var, foreground="red").pack(pady=(6, 0))

        btns = ttk.Frame(frm)
        btns.pack(pady=(10, 0))
        ttk.Button(btns, text="Login", command=self._try_login).pack(side="left", padx=4)
        ttk.Button(btns, text="Quit", command=self._on_close).pack(side="left", padx=4)

        self.bind("<Return>", lambda e: self._try_login())
        pe.focus_set()

        self.update_idletasks()
        try:
            self.master.eval(f"tk::PlaceWindow {self._w} center")
        except tk.TclError:
            pass
        self.wait_visibility()
        try:
            self.grab_set()
        except tk.TclError:
            pass

    def _try_login(self):
        if verify_login(self.store, self.user_var.get().strip(), self.pass_var.get()):
            self.ok = True
            self.destroy()
            return
        self.attempts += 1
        self.err_var.set(f"Login failed ({self.attempts}/3)")
        self.pass_var.set("")
        if self.attempts >= 3:
            messagebox.showerror("Login", "Too many failed attempts. Exiting.", parent=self)
            self.ok = False
            self.destroy()

    def _on_close(self):
        self.ok = False
        self.destroy()


# ---------------------------------------------------------------- client thread
class NodeHandler(threading.Thread):
    def __init__(self, server, sock, addr):
        super().__init__(daemon=True)
        self.server = server
        self.sock = sock
        self.addr = addr
        self.node_id = None
        self.alive = True
        self.send_lock = threading.Lock()

    def run(self):
        buf = b""
        try:
            while self.alive:
                data = self.sock.recv(65536)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if len(line) > MAX_LINE:
                        self.server.log(f"Frame too large from {self.addr[0]} — dropped")
                        buf = b""
                        break
                    if line.strip():
                        self.handle_line(line)
        except (ConnectionResetError, OSError):
            pass
        except Exception as e:
            self.server.log(f"Handler error {self.addr[0]}: {e}")
        finally:
            self.cleanup()

    def handle_line(self, line: bytes):
        try:
            msg = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.server.log("MALFORMED packet dropped")
            return

        mtype = msg.get("type", "")

        if mtype == "HELLO":
            self.node_id = str(msg.get("id", f"anon-{self.addr[1]}"))
            self.server.register(self)
            return

        if self.node_id is None:
            return

        dst = msg.get("dst", "*")
        msg.setdefault("src", self.node_id)

        if mtype == "LIST_NODES":
            # FIX: this was missing entirely — client roster stayed empty
            self.send({"type": "NODES_LIST", "nodes": self.server.online()})
            return

        if mtype == "PONG":
            try:
                latency = (time.time() - float(msg.get("ts", time.time()))) * 1000
                self.server.log(f"PONG from {self.node_id} ({latency:.1f}ms)")
            except (TypeError, ValueError):
                self.server.log(f"PONG from {self.node_id}")
            return

        if mtype == "CMD":
            self.server.log(f"CMD: {self.node_id} -> {dst}: {msg.get('cmd', '')}")
        elif mtype == "CMD_OUTPUT":
            self.server.log(f"CMD_OUTPUT: {self.node_id} -> {dst}")
        elif mtype == "CMD_ERROR":
            self.server.log(f"CMD_ERROR: {self.node_id} -> {dst}: {msg.get('error', '')}")
        elif mtype == "MSG":
            self.server.log(f"MSG: {self.node_id} -> {dst}")
        elif mtype == "FILE_START":
            name = os.path.basename(str(msg.get("name", "file.bin")))
            try:
                size = min(int(msg.get("size", 0)), MAX_FILE_SIZE)
            except (TypeError, ValueError):
                size = 0
            msg["name"] = name
            msg["size"] = size
            self.server.log(f"FILE {name} ({size}B) {self.node_id} -> {dst}")
        elif mtype == "FILE_LIST_REQ":
            self.server.log(f"FILE_LIST_REQ: {self.node_id} -> {dst}")
        elif mtype == "FILE_DOWNLOAD":
            self.server.log(f"FILE_DOWNLOAD: {self.node_id} -> {dst}: {msg.get('name','')}")

        self.server.route(msg, dst, self)

    def send(self, msg: dict):
        with self.send_lock:
            try:
                self.sock.sendall(pack(msg))
            except OSError:
                self.alive = False

    def cleanup(self):
        self.alive = False
        if self.node_id:
            self.server.unregister(self)
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- server core
class RelayServer:
    def __init__(self, gui):
        self.gui = gui
        self.nodes = {}
        self.lock = threading.RLock()
        self.sock = None
        self.running = False
    def log(self, text):
        self.gui.log(text)
    def start(self, host, port):
        if self.running:
            return False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((host, port))
            self.sock.listen(50)
        except OSError as e:
            self.gui.log(f"Bind failed: {e}")
            self.sock = None
            return False
        self.running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()
        self.gui.log(f"Server listening on {host}:{port}")
        return True

    def stop(self):
        self.running = False
        with self.lock:
            for n in list(self.nodes.values()):
                n.send({"type": "SERVER_SHUTDOWN"})
                n.alive = False
                try:
                    n.sock.close()
                except OSError:
                    pass
            self.nodes.clear()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self.gui.schedule_roster_refresh()
        self.gui.log("Server stopped — all nodes disconnected")
        return True

    def accept_loop(self):
        while self.running:
            try:
                s, addr = self.sock.accept()
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                NodeHandler(self, s, addr).start()
                self.gui.log(f"Connection from {addr[0]}:{addr[1]} (awaiting HELLO)")
            except OSError:
                break
            except Exception as e:
                if self.running:
                    self.gui.log(f"Accept error: {e}")

    def register(self, h):
        with self.lock:
            if h.node_id in self.nodes:
                old = self.nodes[h.node_id]
                old.alive = False
                try:
                    old.sock.close()
                except OSError:
                    pass
                self.gui.log(f"Duplicate ID '{h.node_id}' — previous socket closed")
            self.nodes[h.node_id] = h
        self.gui.log(f"Node registered: {h.node_id} @ {h.addr[0]}")
        self.gui.schedule_roster_refresh()

    def unregister(self, h):
        with self.lock:
            if self.nodes.get(h.node_id) is h:
                del self.nodes[h.node_id]
        self.gui.log(f"Node left: {h.node_id}")
        self.gui.schedule_roster_refresh()

    def route(self, msg, dst, sender):
        with self.lock:
            if dst == "*":
                targets = [h for nid, h in self.nodes.items() if h is not sender]
            else:
                targets = [self.nodes[dst]] if dst in self.nodes else []
        if not targets:
            if sender and dst != "*":
                sender.send({"type": "ERROR", "error": f"unknown dest '{dst}'"})
            return
        for h in targets:
            h.send(msg)

    def kick(self, node_id):
        with self.lock:
            h = self.nodes.get(node_id)
        if h:
            h.send({"type": "KICKED"})
            h.alive = False
            try:
                h.sock.close()
            except OSError:
                pass

    def broadcast_gui(self, text):
        self.route({"type": "GUI_BROADCAST", "text": text, "src": "SERVER"}, "*", None)

    def online(self):
        with self.lock:
            return sorted(self.nodes.keys())


# ---------------------------------------------------------------- GUI
class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("All-in-One Relay Server")
        self.root.geometry("960x640")
        self.server = RelayServer(self)
        self.log_q = queue.Queue()
        self._roster_pending = False
        self._build()

        threading.Thread(target=self._fetch_public_ip, daemon=True).start()
        self.root.after(100, self._pump_log)
        self.root.after(5000, self.update_stats)

    def schedule_roster_refresh(self):
        if self._roster_pending:
            return
        self._roster_pending = True
        self.root.after(0, self._do_roster_refresh)

    def _do_roster_refresh(self):
        self._roster_pending = False
        self.refresh_roster()

    def _fetch_public_ip(self):
        ip = fetch_public_ip()
        self.root.after(0, lambda: self._set_public_ip(ip))

    def _set_public_ip(self, ip):
        if ip:
            self.ip_var.set(f"Public IP: {ip}")
            self.root.title(f"All-in-One Relay Server — {ip}")
            self.log(f"Public IP detected: {ip}")
            if ip.startswith("100.") and 64 <= int(ip.split(".")[1]) <= 127:
                self.log("WARNING: This is a CGNAT address — port forwarding will NOT work.")
        else:
            self.ip_var.set("Public IP: unavailable")
            self.log("Could not detect public IP (offline or blocked)")

    def refresh_public_ip(self):
        self.ip_var.set("Public IP: fetching…")
        threading.Thread(target=self._fetch_public_ip, daemon=True).start()

    def _build(self):
        top = ttk.Frame(self.root, padding=6)
        top.pack(fill="x")

        ttk.Label(top, text="Bind IP:").pack(side="left")
        self.host_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(top, textvariable=self.host_var, width=15).pack(side="left", padx=4)

        ttk.Label(top, text="Port:").pack(side="left")
        self.port_var = tk.StringVar(value="5555")
        ttk.Entry(top, textvariable=self.port_var, width=7).pack(side="left", padx=4)

        self.btn_start = ttk.Button(top, text="START", command=self.start)
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop = ttk.Button(top, text="STOP", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="STOPPED")
        # FIX: this label was created but never stored -> AttributeError in start()/stop()
        self.status_lbl = ttk.Label(top, textvariable=self.status_var,
                                    foreground="red", font=("Consolas", 10, "bold"))
        self.status_lbl.pack(side="right", padx=8)

        self.ip_var = tk.StringVar(value="Public IP: fetching…")
        ttk.Label(top, textvariable=self.ip_var, font=("Consolas", 10, "bold"),
                  foreground="#0066cc").pack(side="right", padx=4)
        ttk.Button(top, text="↻", width=3, command=self.refresh_public_ip).pack(side="right")

        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True)

        left = ttk.LabelFrame(main, text="Online Nodes", padding=4)
        left.pack(side="left", fill="y", padx=6, pady=6)
        self.roster = tk.Listbox(left, width=28, exportselection=False)
        self.roster.pack(fill="both", expand=True)
        ttk.Button(left, text="Kick selected", command=self.kick).pack(fill="x", pady=2)
        ttk.Button(left, text="Ping selected", command=self.ping_node).pack(fill="x")

        right = ttk.Notebook(main)
        right.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        tab_msg = ttk.Frame(right)
        right.add(tab_msg, text="Console")
        self.log_box = tk.Text(tab_msg, height=18, state="disabled", wrap="word",
                               font=("Consolas", 9))
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)

        row = ttk.Frame(tab_msg)
        row.pack(fill="x", padx=4, pady=4)
        ttk.Label(row, text="Broadcast:").pack(side="left")
        self.msg_var = tk.StringVar()
        self.msg_entry = ttk.Entry(row, textvariable=self.msg_var)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(row, text="Send", command=self.send_broadcast).pack(side="left")
        self.msg_entry.bind("<Return>", lambda e: self.send_broadcast())

        tab_file = ttk.Frame(right)
        right.add(tab_file, text="Send File")
        ttk.Button(tab_file, text="Choose file & send to selected node",
                   command=self.send_file).pack(pady=8, padx=8, anchor="w")
        self.file_lbl = ttk.Label(tab_file, text="No file queued")
        self.file_lbl.pack(anchor="w", padx=8)
        self.file_path = None

        tab_stats = ttk.Frame(right)
        right.add(tab_stats, text="Stats")
        self.stats_var = tk.StringVar(value="Online nodes: 0")
        ttk.Label(tab_stats, textvariable=self.stats_var,
                  font=("Consolas", 11)).pack(pady=10, anchor="w", padx=8)

    def log(self, text):
        self.log_q.put(f"[{ts()}] {text}")

    def _pump_log(self):
        try:
            while True:
                line = self.log_q.get_nowait()
                self.log_box.configure(state="normal")
                self.log_box.insert("end", line + "\n")
                self.log_box.see("end")
                self.log_box.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(100, self._pump_log)

    def refresh_roster(self):
        ids = self.server.online()
        self.roster.delete(0, "end")
        for nid in ids:
            self.roster.insert("end", nid)
        self.stats_var.set(f"Online nodes: {len(ids)}")

    def update_stats(self):
        self.refresh_roster()
        self.root.after(5000, self.update_stats)

    def _selected_node(self):
        sel = self.roster.curselection()
        return self.roster.get(sel[0]) if sel else None

    def start(self):
        try:
            port = int(self.port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Port must be an integer 1-65535")
            return
        if self.server.start(self.host_var.get().strip(), port):
            self.status_var.set("RUNNING")
            self.status_lbl.configure(foreground="green")
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
        else:
            messagebox.showerror("Error", "Failed to bind — port may be in use")

    def stop(self):
        self.server.stop()
        self.status_var.set("STOPPED")
        self.status_lbl.configure(foreground="red")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def kick(self):
        nid = self._selected_node()
        if nid:
            self.server.kick(nid)
            self.log(f"KICK -> {nid}")

    def ping_node(self):
        nid = self._selected_node()
        if nid:
            self.server.route({"type": "PING", "src": "SERVER", "ts": time.time()}, nid, None)
            self.log(f"PING -> {nid}")

    def send_broadcast(self):
        text = self.msg_var.get().strip()
        if text:
            self.server.broadcast_gui(text)
            self.log(f"SERVER broadcast: {text}")
            self.msg_var.set("")

    def send_file(self):
        nid = self._selected_node()
        if not nid:
            messagebox.showinfo("Send File", "Select a node first")
            return
        path = filedialog.askopenfilename(title="Choose file to send")
        if not path:
            return
        if not self.server.running:
            messagebox.showerror("Send File", "Server is not running")
            return

        name = os.path.basename(path)
        try:
            size = os.path.getsize(path)
            if size > MAX_FILE_SIZE:
                messagebox.showerror("Send File", "File exceeds 512 MB limit")
                return
        except OSError as e:
            messagebox.showerror("Send File", f"Cannot read file: {e}")
            return

        self.file_lbl.configure(text=f"Sending {name} ({size}B) to {nid}...")
        self.log(f"FILE push: {name} ({size}B) -> {nid}")

        def worker():
            handler = self.server.nodes.get(nid)
            if not handler:
                self.root.after(0, lambda: self.file_lbl.configure(text="Node went offline"))
                return
            handler.send({"type": "FILE_START", "src": "SERVER", "name": name, "size": size})
            sent = 0
            try:
                with open(path, "rb") as f:
                    while sent < size:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        handler.send({"type": "FILE_CHUNK", "src": "SERVER", "name": name,
                                      "data": base64.b64encode(chunk).decode("ascii")})
                        sent += len(chunk)
                handler.send({"type": "FILE_END", "src": "SERVER", "name": name})
                self.root.after(0, lambda: self.file_lbl.configure(
                    text=f"Sent: {name} ({sent}B) to {nid}"))
                self.log(f"FILE push complete: {name} -> {nid}")
            except Exception as e:
                self.log(f"FILE push error: {e}")
                self.root.after(0, lambda: self.file_lbl.configure(text="Send failed"))

        threading.Thread(target=worker, daemon=True).start()


def main():
    store = load_or_create_auth()
    root = tk.Tk()
    root.withdraw()
    login = LoginDialog(root, store)
    root.wait_window(login)
    if not login.ok:
        root.destroy()
        return
    root.deiconify()
    ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
