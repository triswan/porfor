#!/usr/bin/env python3
"""
SSH Multi-Port Forwarder GUI
A modern Tkinter-based SSH Port Forwarding manager supporting multiple local-to-remote ports,
quick SSH command parsing/generation, session profiles, and both Paramiko and OpenSSH backends.

Example target command:
ssh -N -L 8002:localhost:8002 -L 5173:localhost:5173 -L 19000:localhost:19000 user@your-server-ip
"""

import sys
import os
import json
import socket
import select
import shlex
import re
import time
import threading
import subprocess
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Try importing paramiko
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


# Configuration path in user's home directory (kept out of git repository)
CONFIG_FILE = Path.home() / ".ssh_multi_port_forwarder.json"

# Default profile template
DEFAULT_PROFILES = {
    "default": {
        "name": "Default",
        "host": "",
        "port": "22",
        "user": "",
        "auth_type": "password",
        "key_path": "",
        "save_password": True,
        "password": "",
        "engine": "paramiko",
        "ports": [
            {
                "id": "1",
                "enabled": True,
                "local_port": 8002,
                "remote_host": "localhost",
                "remote_port": 8002,
                "label": "API / Backend"
            },
            {
                "id": "2",
                "enabled": True,
                "local_port": 5173,
                "remote_host": "localhost",
                "remote_port": 5173,
                "label": "Frontend (Vite)"
            },
            {
                "id": "3",
                "enabled": True,
                "local_port": 19000,
                "remote_host": "localhost",
                "remote_port": 19000,
                "label": "Expo / Dev Server"
            }
        ]
    }
}


def parse_ssh_command(cmd_str):
    """
    Parse an SSH command string into connection details and port mappings.
    Handles:
    ssh -N -L 8002:localhost:8002 -L 5173:localhost:5173 -L 19000:localhost:19000 user@your-server-ip
    """
    cmd_str = cmd_str.strip()
    if not cmd_str:
        return None

    try:
        tokens = shlex.split(cmd_str)
    except Exception:
        tokens = cmd_str.split()

    host = ""
    user = ""
    port = "22"
    key_path = ""
    ports = []

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "ssh":
            i += 1
            continue

        if tok == "-p" and i + 1 < len(tokens):
            port = tokens[i + 1]
            i += 2
            continue

        if tok == "-i" and i + 1 < len(tokens):
            key_path = tokens[i + 1]
            i += 2
            continue

        if tok == "-L" and i + 1 < len(tokens):
            rule_str = tokens[i + 1]
            parsed_rule = parse_port_rule(rule_str)
            if parsed_rule:
                ports.append(parsed_rule)
            i += 2
            continue

        if tok.startswith("-L") and len(tok) > 2:
            rule_str = tok[2:]
            parsed_rule = parse_port_rule(rule_str)
            if parsed_rule:
                ports.append(parsed_rule)
            i += 1
            continue

        if tok.startswith("-"):
            i += 1
            continue

        # Target user@host or host
        if "@" in tok:
            user, host = tok.split("@", 1)
        elif not host and not tok.startswith("-"):
            host = tok

        i += 1

    return {
        "host": host,
        "user": user,
        "port": port,
        "key_path": key_path,
        "ports": ports
    }


def parse_port_rule(rule_str):
    """
    Parses port forwarding specification:
    - [bind_address:]local_port:remote_host:remote_port
    - local_port:remote_port
    """
    parts = rule_str.split(":")
    try:
        if len(parts) == 4:
            return {
                "local_port": int(parts[1]),
                "remote_host": parts[2] or "localhost",
                "remote_port": int(parts[3]),
                "enabled": True,
                "label": f"Port {parts[1]}"
            }
        elif len(parts) == 3:
            return {
                "local_port": int(parts[0]),
                "remote_host": parts[1] or "localhost",
                "remote_port": int(parts[2]),
                "enabled": True,
                "label": f"Port {parts[0]}"
            }
        elif len(parts) == 2:
            return {
                "local_port": int(parts[0]),
                "remote_host": "localhost",
                "remote_port": int(parts[1]),
                "enabled": True,
                "label": f"Port {parts[0]}"
            }
        elif len(parts) == 1 and parts[0].isdigit():
            p = int(parts[0])
            return {
                "local_port": p,
                "remote_host": "localhost",
                "remote_port": p,
                "enabled": True,
                "label": f"Port {p}"
            }
    except Exception:
        pass
    return None


class ParamikoForwarder:
    """Handles multi-port SSH forwarding using Paramiko direct-tcpip channels."""

    def __init__(self, log_cb, status_cb, port_stat_cb):
        self.log = log_cb
        self.set_status = status_cb
        self.set_port_stat = port_stat_cb
        self.client = None
        self.transport = None
        self.stop_event = threading.Event()
        self.listener_sockets = []
        self.active_threads = []
        self.active_conns = 0
        self.conns_lock = threading.Lock()

    def is_connected(self):
        return self.transport is not None and self.transport.is_active()

    def connect(self, host, port, user, auth_type, password="", key_path="", passphrase=None):
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("Modul paramiko belum terinstal. Silakan jalankan 'pip install paramiko'.")

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.log(f"Menghubungi SSH Server {user}@{host}:{port}...", "info")
        self.set_status(f"Connecting to {host}:{port}...", "connecting")

        connect_kwargs = {
            "hostname": host,
            "port": int(port),
            "username": user,
            "timeout": 12,
            "banner_timeout": 15,
        }

        if auth_type == "password":
            connect_kwargs["password"] = password
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False
        elif auth_type == "key":
            if not os.path.exists(key_path):
                raise FileNotFoundError(f"File private key tidak ditemukan: {key_path}")
            connect_kwargs["key_filename"] = key_path
            if passphrase:
                connect_kwargs["passphrase"] = passphrase
            connect_kwargs["look_for_keys"] = False
        elif auth_type == "agent":
            connect_kwargs["look_for_keys"] = True
            connect_kwargs["allow_agent"] = True

        self.client.connect(**connect_kwargs)
        self.transport = self.client.get_transport()
        if not self.transport or not self.transport.is_active():
            raise ConnectionError("Gagal memulai SSH transport!")

        self.transport.set_keepalive(30)
        self.log(f"Berhasil terhubung ke {host}:{port}!", "success")

    def start_tunnels(self, rules):
        """Start listening on local ports and forwarding traffic."""
        self.stop_event.clear()
        self.listener_sockets.clear()

        started_count = 0
        for rule in rules:
            if not rule.get("enabled", True):
                self.set_port_stat(rule["id"], "Disabled")
                continue

            local_port = int(rule["local_port"])
            remote_host = rule.get("remote_host", "localhost")
            remote_port = int(rule["remote_port"])
            rule_id = rule["id"]

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", local_port))
                sock.listen(10)
                sock.settimeout(0.5)
                self.listener_sockets.append((sock, local_port))

                t = threading.Thread(
                    target=self._listen_worker,
                    args=(sock, local_port, remote_host, remote_port, rule_id),
                    daemon=True
                )
                t.start()
                self.active_threads.append(t)
                started_count += 1
                self.set_port_stat(rule_id, "● Listening")
                self.log(f"Tunnel aktif: localhost:{local_port} -> {remote_host}:{remote_port}", "success")
            except Exception as e:
                self.set_port_stat(rule_id, f"✕ Error: {e}")
                self.log(f"Gagal bind port lokal {local_port}: {e}", "error")

        if started_count == 0:
            raise RuntimeError("Tidak ada port forwarding yang berhasil dijalankan!")

        self.set_status(f"Active ({started_count} ports)", "active")
        self.log(f"Forwarding aktif untuk {started_count} port.", "info")

    def _listen_worker(self, listener_sock, local_port, remote_host, remote_port, rule_id):
        while not self.stop_event.is_set():
            try:
                client_sock, client_addr = listener_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                break

            if self.stop_event.is_set():
                client_sock.close()
                break

            t = threading.Thread(
                target=self._forward_conn,
                args=(client_sock, client_addr, local_port, remote_host, remote_port, rule_id),
                daemon=True
            )
            t.start()

        try:
            listener_sock.close()
        except Exception:
            pass

    def _forward_conn(self, client_sock, client_addr, local_port, remote_host, remote_port, rule_id):
        with self.conns_lock:
            self.active_conns += 1
            conns = self.active_conns
        self.set_port_stat(rule_id, f"● Connected ({conns})")

        chan = None
        try:
            if not self.transport or not self.transport.is_active():
                self.log(f"[Port {local_port}] Transport SSH terputus.", "error")
                client_sock.close()
                return

            chan = self.transport.open_channel(
                "direct-tcpip",
                (remote_host, remote_port),
                client_addr,
                timeout=10
            )

            if chan is None:
                self.log(f"[Port {local_port}] SSH Server menolak forward ke {remote_host}:{remote_port}", "error")
                client_sock.close()
                return

            close_evt = threading.Event()
            t1 = threading.Thread(target=self._pump, args=(client_sock, chan, close_evt), daemon=True)
            t2 = threading.Thread(target=self._pump, args=(chan, client_sock, close_evt), daemon=True)
            t1.start()
            t2.start()

            while not close_evt.is_set() and not self.stop_event.is_set() and t1.is_alive() and t2.is_alive():
                time.sleep(0.3)
            close_evt.set()

        except Exception as e:
            if not self.stop_event.is_set():
                self.log(f"[Port {local_port}] Error koneksi: {e}", "warning")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            try:
                if chan:
                    chan.close()
            except Exception:
                pass

            with self.conns_lock:
                self.active_conns = max(0, self.active_conns - 1)
                conns = self.active_conns
            if not self.stop_event.is_set():
                self.set_port_stat(rule_id, "● Listening" if conns == 0 else f"● Connected ({conns})")

    def _pump(self, src, dst, close_evt):
        try:
            if hasattr(src, "settimeout"):
                src.settimeout(1.0)
        except Exception:
            pass

        while not close_evt.is_set() and not self.stop_event.is_set():
            try:
                data = src.recv(8192)
                if not data:
                    break
                dst.sendall(data)
            except socket.timeout:
                continue
            except Exception:
                break
        close_evt.set()

    def stop(self):
        self.stop_event.set()
        for sock, _ in self.listener_sockets:
            try:
                sock.close()
            except Exception:
                pass
        self.listener_sockets.clear()

        if self.transport:
            try:
                self.transport.close()
            except Exception:
                pass
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

        self.transport = None
        self.client = None
        with self.conns_lock:
            self.active_conns = 0


class OpenSSHForwarder:
    """Runs native 'ssh -N -L ...' subprocess and pipes logs."""

    def __init__(self, log_cb, status_cb):
        self.log = log_cb
        self.set_status = status_cb
        self.process = None
        self.stop_requested = False

    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def start(self, cmd_args):
        self.stop_requested = False
        self.log(f"Menjalankan OpenSSH: {' '.join(cmd_args)}", "info")
        self.set_status("OpenSSH Running", "active")

        try:
            self.process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except Exception as e:
            self.set_status("OpenSSH Error", "error")
            raise RuntimeError(f"Gagal menjalankan ssh: {e}")

        threading.Thread(target=self._read_pipe, args=(self.process.stdout, "info"), daemon=True).start()
        threading.Thread(target=self._read_pipe, args=(self.process.stderr, "warning"), daemon=True).start()
        threading.Thread(target=self._monitor_proc, daemon=True).start()

    def _read_pipe(self, pipe, tag):
        try:
            for line in iter(pipe.readline, ''):
                line = line.strip()
                if line:
                    self.log(f"[OpenSSH] {line}", tag)
        except Exception:
            pass

    def _monitor_proc(self):
        code = self.process.wait()
        if not self.stop_requested:
            if code == 0:
                self.log("Proses SSH selesai secara normal.", "info")
                self.set_status("SSH Stopped", "idle")
            else:
                self.log(f"Proses SSH berhenti dengan kode exit: {code}", "error")
                self.set_status("SSH Error", "error")

    def stop(self):
        self.stop_requested = True
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.process = None
        self.set_status("SSH Stopped", "idle")


class SSHMultiPortForwarderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Multi-Port Forwarder")
        self.root.geometry("860x820")
        self.root.minsize(760, 680)

        # State
        self.is_forwarding = False
        self.paramiko_engine = ParamikoForwarder(self.log, self.update_status_badge, self.update_port_status)
        self.openssh_engine = OpenSSHForwarder(self.log, self.update_status_badge)
        self.profiles = {}
        self.current_profile_key = "default"
        self.next_port_id = 1

        self.setup_styles()
        self.build_ui()
        self.load_profiles()
        self.apply_profile(self.current_profile_key)
        self.update_command_preview()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_styles(self):
        """Configures clean styling for Tkinter ttk."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.bg_main = "#0f172a"      # slate-900
        self.bg_card = "#1e293b"      # slate-800
        self.bg_input = "#334155"     # slate-700
        self.text_main = "#f8fafc"    # slate-50
        self.text_muted = "#94a3b8"   # slate-400
        self.accent_blue = "#38bdf8"  # sky-400
        self.accent_green = "#10b981" # emerald-500
        self.accent_red = "#ef4444"   # rose-500
        self.border_col = "#475569"   # slate-600

        self.root.configure(bg=self.bg_main)

        style.configure(".", background=self.bg_main, foreground=self.text_main, font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=self.bg_card, relief="flat")
        style.configure("Header.TLabel", background=self.bg_main, foreground=self.text_main, font=("Segoe UI", 13, "bold"))
        style.configure("Subheader.TLabel", background=self.bg_card, foreground=self.accent_blue, font=("Segoe UI", 10, "bold"))
        style.configure("Muted.TLabel", background=self.bg_card, foreground=self.text_muted, font=("Segoe UI", 9))

        style.configure("TLabel", background=self.bg_card, foreground=self.text_main)
        style.configure("TEntry", fieldbackground=self.bg_input, foreground=self.text_main, insertcolor=self.text_main)
        style.configure("TCombobox", fieldbackground=self.bg_input, foreground=self.text_main)
        style.configure("TCheckbutton", background=self.bg_card, foreground=self.text_main)
        style.configure("TRadiobutton", background=self.bg_card, foreground=self.text_main)

        # Treeview
        style.configure(
            "Treeview",
            background=self.bg_card,
            foreground=self.text_main,
            fieldbackground=self.bg_card,
            rowheight=26,
            bordercolor=self.border_col,
            font=("Segoe UI", 9)
        )
        style.configure("Treeview.Heading", background=self.bg_input, foreground=self.text_main, font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#0284c7")], foreground=[("selected", "#ffffff")])

    def build_ui(self):
        main_container = tk.Frame(self.root, bg=self.bg_main, padx=14, pady=10)
        main_container.pack(fill=tk.BOTH, expand=True)

        # 1. Header & Status Bar
        header_frame = tk.Frame(main_container, bg=self.bg_main)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_lbl = ttk.Label(header_frame, text="SSH Multi-Port Forwarder", style="Header.TLabel")
        title_lbl.pack(side=tk.LEFT)

        self.status_badge = tk.Label(
            header_frame,
            text="○ Idle (Disconnected)",
            bg="#334155",
            fg="#cbd5e1",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
            relief="flat"
        )
        self.status_badge.pack(side=tk.RIGHT)

        # Profile selection
        profile_frame = tk.Frame(header_frame, bg=self.bg_main)
        profile_frame.pack(side=tk.RIGHT, padx=12)

        ttk.Label(profile_frame, text="Profile:", background=self.bg_main).pack(side=tk.LEFT, padx=(0, 4))
        self.profile_combo = ttk.Combobox(profile_frame, width=22, state="readonly")
        self.profile_combo.pack(side=tk.LEFT, padx=2)
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_change)

        save_prof_btn = tk.Button(profile_frame, text="Save", bg=self.bg_input, fg=self.text_main,
                                  font=("Segoe UI", 8, "bold"), command=self.save_current_profile, relief="flat", padx=8)
        save_prof_btn.pack(side=tk.LEFT, padx=2)

        new_prof_btn = tk.Button(profile_frame, text="+ New", bg=self.bg_input, fg=self.text_main,
                                 font=("Segoe UI", 8, "bold"), command=self.create_new_profile_dialog, relief="flat", padx=8)
        new_prof_btn.pack(side=tk.LEFT, padx=2)

        # 2. SSH Connection Settings
        ssh_card = tk.LabelFrame(main_container, text=" SSH Server Connection ", bg=self.bg_card,
                                 fg=self.accent_blue, font=("Segoe UI", 10, "bold"), padx=12, pady=8, bd=1)
        ssh_card.pack(fill=tk.X, pady=(0, 8))

        row1 = tk.Frame(ssh_card, bg=self.bg_card)
        row1.pack(fill=tk.X, pady=3)

        ttk.Label(row1, text="Host / IP:").pack(side=tk.LEFT, padx=(0, 4))
        self.host_entry = ttk.Entry(row1, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.host_entry.bind("<KeyRelease>", lambda e: self.update_command_preview())

        ttk.Label(row1, text="Port:").pack(side=tk.LEFT, padx=(0, 4))
        self.port_entry = ttk.Entry(row1, width=6)
        self.port_entry.insert(0, "22")
        self.port_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.port_entry.bind("<KeyRelease>", lambda e: self.update_command_preview())

        ttk.Label(row1, text="User:").pack(side=tk.LEFT, padx=(0, 4))
        self.user_entry = ttk.Entry(row1, width=14)
        self.user_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.user_entry.bind("<KeyRelease>", lambda e: self.update_command_preview())

        self.test_btn = tk.Button(row1, text="Test Connection", bg=self.bg_input, fg=self.text_main,
                                  font=("Segoe UI", 9, "bold"), relief="flat", padx=10, command=self.test_ssh_connection)
        self.test_btn.pack(side=tk.RIGHT)

        row2 = tk.Frame(ssh_card, bg=self.bg_card)
        row2.pack(fill=tk.X, pady=3)

        ttk.Label(row2, text="Auth Method:").pack(side=tk.LEFT, padx=(0, 4))
        self.auth_var = tk.StringVar(value="password")
        auth_cb = ttk.Combobox(row2, textvariable=self.auth_var, values=["password", "key", "agent"], width=10, state="readonly")
        auth_cb.pack(side=tk.LEFT, padx=(0, 10))
        auth_cb.bind("<<ComboboxSelected>>", self.on_auth_type_changed)

        self.pwd_frame = tk.Frame(row2, bg=self.bg_card)
        self.pwd_frame.pack(side=tk.LEFT, fill=tk.X)

        ttk.Label(self.pwd_frame, text="Password:").pack(side=tk.LEFT, padx=(0, 4))
        self.pwd_entry = ttk.Entry(self.pwd_frame, show="*", width=16)
        self.pwd_entry.pack(side=tk.LEFT, padx=(0, 6))

        self.show_pwd_var = tk.BooleanVar(value=False)
        show_pwd_cb = ttk.Checkbutton(self.pwd_frame, text="Show", variable=self.show_pwd_var, command=self.toggle_show_password)
        show_pwd_cb.pack(side=tk.LEFT)

        self.key_frame = tk.Frame(row2, bg=self.bg_card)
        ttk.Label(self.key_frame, text="Private Key:").pack(side=tk.LEFT, padx=(0, 4))
        self.key_entry = ttk.Entry(self.key_frame, width=28)
        self.key_entry.pack(side=tk.LEFT, padx=(0, 4))
        browse_key_btn = tk.Button(self.key_frame, text="Browse...", bg=self.bg_input, fg=self.text_main,
                                   font=("Segoe UI", 8), command=self.browse_key_file, relief="flat", padx=6)
        browse_key_btn.pack(side=tk.LEFT)

        # 3. Port Forwarding Rules Table
        ports_card = tk.LabelFrame(main_container, text=" Forwarded Ports (-L local:remote_host:remote) ", bg=self.bg_card,
                                   fg=self.accent_blue, font=("Segoe UI", 10, "bold"), padx=10, pady=8, bd=1)
        ports_card.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        add_bar = tk.Frame(ports_card, bg=self.bg_card)
        add_bar.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(add_bar, text="Local Port:").pack(side=tk.LEFT, padx=(0, 2))
        self.new_local_port = ttk.Entry(add_bar, width=7)
        self.new_local_port.pack(side=tk.LEFT, padx=(0, 8))
        self.new_local_port.bind("<KeyRelease>", self.on_local_port_typing)

        ttk.Label(add_bar, text="Remote Host:").pack(side=tk.LEFT, padx=(0, 2))
        self.new_remote_host = ttk.Entry(add_bar, width=12)
        self.new_remote_host.insert(0, "localhost")
        self.new_remote_host.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(add_bar, text="Remote Port:").pack(side=tk.LEFT, padx=(0, 2))
        self.new_remote_port = ttk.Entry(add_bar, width=7)
        self.new_remote_port.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(add_bar, text="Label:").pack(side=tk.LEFT, padx=(0, 2))
        self.new_label = ttk.Entry(add_bar, width=14)
        self.new_label.pack(side=tk.LEFT, padx=(0, 10))

        add_btn = tk.Button(add_bar, text="+ Add Rule", bg=self.accent_blue, fg="#0f172a",
                            font=("Segoe UI", 9, "bold"), command=self.add_port_rule, relief="flat", padx=10)
        add_btn.pack(side=tk.LEFT, padx=2)

        batch_btn = tk.Button(add_bar, text="Batch Add...", bg=self.bg_input, fg=self.text_main,
                              font=("Segoe UI", 9), command=self.open_batch_dialog, relief="flat", padx=8)
        batch_btn.pack(side=tk.LEFT, padx=4)

        tree_frame = tk.Frame(ports_card, bg=self.bg_card)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("enabled", "local", "remote_target", "label", "status")
        self.port_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=5, selectmode="extended")
        
        self.column_titles = {
            "enabled": "Active",
            "local": "Local Port",
            "remote_target": "Remote Target",
            "label": "Service / Description",
            "status": "Tunnel Status"
        }
        self.sort_state = {"col": None, "reverse": False}

        for col, title in self.column_titles.items():
            self.port_tree.heading(col, text=title, command=lambda c=col: self.sort_tree_column(c))

        self.port_tree.column("enabled", width=70, anchor="center")
        self.port_tree.column("local", width=95, anchor="center")
        self.port_tree.column("remote_target", width=170, anchor="w")
        self.port_tree.column("label", width=180, anchor="w")
        self.port_tree.column("status", width=150, anchor="w")

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=tree_scroll.set)

        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.port_tree.bind("<Double-1>", self.on_rule_double_click)
        self.port_tree.bind("<F2>", self.on_f2_pressed)
        self.root.bind("<F2>", self.on_f2_pressed)

        tbl_actions = tk.Frame(ports_card, bg=self.bg_card)
        tbl_actions.pack(fill=tk.X, pady=(6, 0))

        tk.Button(tbl_actions, text="Edit Selected...", bg=self.bg_input, fg=self.accent_blue,
                  font=("Segoe UI", 8, "bold"), command=self.edit_selected_rule, relief="flat", padx=8).pack(side=tk.LEFT, padx=2)
        tk.Button(tbl_actions, text="Toggle Active", bg=self.bg_input, fg=self.text_main,
                  font=("Segoe UI", 8), command=self.toggle_selected_rules, relief="flat", padx=8).pack(side=tk.LEFT, padx=2)
        tk.Button(tbl_actions, text="Delete Selected", bg=self.bg_input, fg=self.accent_red,
                  font=("Segoe UI", 8), command=self.delete_selected_rules, relief="flat", padx=8).pack(side=tk.LEFT, padx=2)
        tk.Button(tbl_actions, text="Clear All", bg=self.bg_input, fg=self.text_muted,
                  font=("Segoe UI", 8), command=self.clear_all_rules, relief="flat", padx=8).pack(side=tk.LEFT, padx=2)

        ttk.Label(tbl_actions, text="Tip: Klik judul untuk sort | Double-click / F2 untuk edit", style="Muted.TLabel").pack(side=tk.RIGHT)

        # 4. Command Preview & Quick Import
        cmd_card = tk.LabelFrame(main_container, text=" SSH Command (-L Multi-Port) ", bg=self.bg_card,
                                 fg=self.accent_blue, font=("Segoe UI", 10, "bold"), padx=10, pady=6, bd=1)
        cmd_card.pack(fill=tk.X, pady=(0, 8))

        cmd_row = tk.Frame(cmd_card, bg=self.bg_card)
        cmd_row.pack(fill=tk.X)

        self.cmd_preview_var = tk.StringVar()
        self.cmd_entry = tk.Entry(cmd_row, textvariable=self.cmd_preview_var, bg=self.bg_input, fg="#7dd3fc",
                                  font=("Courier New", 9), relief="flat")
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6), ipady=3)

        copy_btn = tk.Button(cmd_row, text="Copy", bg=self.bg_input, fg=self.text_main,
                             font=("Segoe UI", 8, "bold"), command=self.copy_command_to_clipboard, relief="flat", padx=10)
        copy_btn.pack(side=tk.LEFT, padx=2)

        import_btn = tk.Button(cmd_row, text="Import / Parse", bg=self.accent_blue, fg="#0f172a",
                               font=("Segoe UI", 8, "bold"), command=self.open_import_dialog, relief="flat", padx=10)
        import_btn.pack(side=tk.LEFT, padx=2)

        # 5. Execution Bar & Engine
        exec_bar = tk.Frame(main_container, bg=self.bg_main)
        exec_bar.pack(fill=tk.X, pady=(0, 8))

        eng_frame = tk.Frame(exec_bar, bg=self.bg_main)
        eng_frame.pack(side=tk.LEFT)
        ttk.Label(eng_frame, text="Engine:", background=self.bg_main, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.engine_var = tk.StringVar(value="paramiko")
        ttk.Radiobutton(eng_frame, text="Paramiko (Built-in)", variable=self.engine_var, value="paramiko").pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(eng_frame, text="OpenSSH (ssh CLI)", variable=self.engine_var, value="openssh").pack(side=tk.LEFT, padx=4)

        self.action_btn = tk.Button(
            exec_bar,
            text="▶ START FORWARDING",
            bg=self.accent_green,
            fg="#ffffff",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            padx=20,
            pady=6,
            command=self.toggle_forwarding,
            cursor="hand2"
        )
        self.action_btn.pack(side=tk.RIGHT)

        # 6. Log Console
        log_card = tk.LabelFrame(main_container, text=" Activity Log ", bg=self.bg_card,
                                 fg=self.accent_blue, font=("Segoe UI", 10, "bold"), padx=8, pady=6, bd=1)
        log_card.pack(fill=tk.BOTH, expand=True)

        log_toolbar = tk.Frame(log_card, bg=self.bg_card)
        log_toolbar.pack(fill=tk.X, pady=(0, 4))

        self.autoscroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_toolbar, text="Auto-scroll", variable=self.autoscroll_var).pack(side=tk.LEFT)

        clear_log_btn = tk.Button(log_toolbar, text="Clear Log", bg=self.bg_input, fg=self.text_muted,
                                  font=("Segoe UI", 8), command=self.clear_log, relief="flat", padx=6)
        clear_log_btn.pack(side=tk.RIGHT)

        log_frame = tk.Frame(log_card, bg=self.bg_card)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, bg="#020617", fg="#f1f5f9", font=("Consolas", 9),
                                relief="flat", wrap=tk.WORD, height=7, state=tk.DISABLED)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text.tag_configure("info", foreground="#94a3b8")
        self.log_text.tag_configure("success", foreground="#34d399")
        self.log_text.tag_configure("warning", foreground="#fbbf24")
        self.log_text.tag_configure("error", foreground="#f87171")
        self.log_text.tag_configure("time", foreground="#64748b")

    # ==========================
    # Callbacks & Helpers
    # ==========================
    def on_local_port_typing(self, event=None):
        val = self.new_local_port.get().strip()
        curr_rem = self.new_remote_port.get().strip()
        if val.isdigit() and (not curr_rem or curr_rem == val[:-1]):
            self.new_remote_port.delete(0, tk.END)
            self.new_remote_port.insert(0, val)

    def on_auth_type_changed(self, event=None):
        val = self.auth_var.get()
        if val == "password":
            self.pwd_frame.pack(side=tk.LEFT, fill=tk.X)
            self.key_frame.pack_forget()
        elif val == "key":
            self.pwd_frame.pack_forget()
            self.key_frame.pack(side=tk.LEFT, fill=tk.X)
        else: # agent
            self.pwd_frame.pack_forget()
            self.key_frame.pack_forget()

    def toggle_show_password(self):
        self.pwd_entry.config(show="" if self.show_pwd_var.get() else "*")

    def browse_key_file(self):
        f = filedialog.askopenfilename(
            title="Pilih Private Key File",
            filetypes=[("All Files", "*.*"), ("PEM / RSA Key", "*.pem;*.key;id_*")]
        )
        if f:
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, f)
            self.update_command_preview()

    def add_port_rule(self):
        local_p = self.new_local_port.get().strip()
        rem_host = self.new_remote_host.get().strip() or "localhost"
        rem_p = self.new_remote_port.get().strip() or local_p
        label = self.new_label.get().strip() or f"Port {local_p}"

        if not local_p.isdigit() or not rem_p.isdigit():
            messagebox.showwarning("Input Error", "Port harus berupa angka valid (1 - 65535).")
            return

        l_val = int(local_p)
        r_val = int(rem_p)
        if not (1 <= l_val <= 65535) or not (1 <= r_val <= 65535):
            messagebox.showwarning("Input Error", "Nomor port harus berada dalam rentang 1 - 65535.")
            return

        rule_id = str(self.next_port_id)
        self.next_port_id += 1

        self.port_tree.insert(
            "",
            tk.END,
            iid=rule_id,
            values=("✓ Enabled", l_val, f"{rem_host}:{r_val}", label, "○ Idle")
        )

        self.new_local_port.delete(0, tk.END)
        self.new_remote_port.delete(0, tk.END)
        self.new_label.delete(0, tk.END)
        self.update_command_preview()

    def open_batch_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Batch Add Ports")
        dialog.geometry("400x260")
        dialog.configure(bg=self.bg_card)
        dialog.transient(self.root)
        dialog.update_idletasks()
        try:
            dialog.grab_set()
        except tk.TclError:
            try:
                dialog.wait_visibility()
                dialog.grab_set()
            except tk.TclError:
                pass

        tk.Label(dialog, text="Masukkan nomor port yang ingin di-forward:", bg=self.bg_card,
                 fg=self.text_main, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        tk.Label(dialog, text="Pisahkan dengan koma atau spasi (contoh: 8002, 5173, 19000)", bg=self.bg_card,
                 fg=self.text_muted, font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(0, 8))

        entry_text = tk.Text(dialog, bg=self.bg_input, fg=self.text_main, font=("Consolas", 10), height=4)
        entry_text.insert(tk.END, "8002, 5173, 19000")
        entry_text.pack(fill=tk.BOTH, expand=True, padx=14, pady=4)

        btn_row = tk.Frame(dialog, bg=self.bg_card)
        btn_row.pack(fill=tk.X, padx=14, pady=10)

        def apply_batch():
            raw = entry_text.get("1.0", tk.END).strip()
            tokens = re.split(r"[\s,;]+", raw)
            added = 0
            for t in tokens:
                t = t.strip()
                if not t:
                    continue
                if ":" in t:
                    parts = t.split(":")
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        lp, rp = int(parts[0]), int(parts[1])
                    else:
                        continue
                elif t.isdigit():
                    lp = rp = int(t)
                else:
                    continue

                if 1 <= lp <= 65535 and 1 <= rp <= 65535:
                    rule_id = str(self.next_port_id)
                    self.next_port_id += 1
                    self.port_tree.insert(
                        "",
                        tk.END,
                        iid=rule_id,
                        values=("✓ Enabled", lp, f"localhost:{rp}", f"Port {lp}", "○ Idle")
                    )
                    added += 1

            self.update_command_preview()
            dialog.destroy()
            self.log(f"Batch add: {added} port berhasil ditambahkan.", "info")

        tk.Button(btn_row, text="Add All", bg=self.accent_blue, fg="#0f172a", font=("Segoe UI", 9, "bold"),
                  command=apply_batch, relief="flat", padx=10).pack(side=tk.RIGHT, padx=4)
        tk.Button(btn_row, text="Cancel", bg=self.bg_input, fg=self.text_main,
                  command=dialog.destroy, relief="flat", padx=10).pack(side=tk.RIGHT)

    def edit_selected_rule(self):
        sel = self.port_tree.selection()
        if not sel:
            messagebox.showinfo("Pilih Rule", "Silakan pilih salah satu port rule di tabel yang ingin diedit.")
            return

        if len(sel) > 1:
            messagebox.showinfo("Pilih Satu Rule", "Silakan pilih hanya satu port rule di tabel untuk diedit.")
            return

        item_id = sel[0]
        vals = list(self.port_tree.item(item_id, "values"))
        if not vals:
            return

        is_enabled = "Enabled" in str(vals[0])
        current_local = str(vals[1])
        remote_target = str(vals[2])
        if ":" in remote_target:
            parts = remote_target.rsplit(":", 1)
            current_remote_host = parts[0]
            current_remote_port = parts[1]
        else:
            current_remote_host = "localhost"
            current_remote_port = remote_target
        current_label = str(vals[3])

        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Port Rule")
        dialog.geometry("440x330")
        dialog.resizable(False, False)
        dialog.configure(bg=self.bg_card)
        dialog.transient(self.root)
        dialog.update_idletasks()
        try:
            dialog.grab_set()
        except tk.TclError:
            try:
                dialog.wait_visibility()
                dialog.grab_set()
            except tk.TclError:
                pass

        # Header
        header = tk.Frame(dialog, bg=self.bg_card)
        header.pack(fill=tk.X, padx=16, pady=(16, 10))
        tk.Label(header, text="Edit Port Forwarding Rule", bg=self.bg_card,
                 fg=self.accent_blue, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(header, text="Ubah parameter port mapping dan deskripsi layanan.", bg=self.bg_card,
                 fg=self.text_muted, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

        form_frame = tk.Frame(dialog, bg=self.bg_card)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 6))

        # Local Port
        row_lp = tk.Frame(form_frame, bg=self.bg_card)
        row_lp.pack(fill=tk.X, pady=4)
        tk.Label(row_lp, text="Local Port:", width=15, anchor="w", bg=self.bg_card,
                 fg=self.text_main, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        entry_lp = ttk.Entry(row_lp, width=24)
        entry_lp.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry_lp.insert(0, current_local)

        # Remote Host
        row_rh = tk.Frame(form_frame, bg=self.bg_card)
        row_rh.pack(fill=tk.X, pady=4)
        tk.Label(row_rh, text="Remote Host:", width=15, anchor="w", bg=self.bg_card,
                 fg=self.text_main, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        entry_rh = ttk.Entry(row_rh, width=24)
        entry_rh.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry_rh.insert(0, current_remote_host)

        # Remote Port
        row_rp = tk.Frame(form_frame, bg=self.bg_card)
        row_rp.pack(fill=tk.X, pady=4)
        tk.Label(row_rp, text="Remote Port:", width=15, anchor="w", bg=self.bg_card,
                 fg=self.text_main, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        entry_rp = ttk.Entry(row_rp, width=24)
        entry_rp.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry_rp.insert(0, current_remote_port)

        # Service / Label
        row_lbl = tk.Frame(form_frame, bg=self.bg_card)
        row_lbl.pack(fill=tk.X, pady=4)
        tk.Label(row_lbl, text="Service / Label:", width=15, anchor="w", bg=self.bg_card,
                 fg=self.text_main, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        entry_lbl = ttk.Entry(row_lbl, width=24)
        entry_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry_lbl.insert(0, current_label)

        # Enabled Checkbutton
        enabled_var = tk.BooleanVar(value=is_enabled)
        row_en = tk.Frame(form_frame, bg=self.bg_card)
        row_en.pack(fill=tk.X, pady=(6, 4))
        tk.Label(row_en, text="", width=15, bg=self.bg_card).pack(side=tk.LEFT)
        ttk.Checkbutton(row_en, text="Active / Enabled", variable=enabled_var).pack(side=tk.LEFT)

        # Buttons
        btn_row = tk.Frame(dialog, bg=self.bg_card)
        btn_row.pack(fill=tk.X, padx=16, pady=(10, 16))

        def save_edits():
            lp_str = entry_lp.get().strip()
            rh_str = entry_rh.get().strip() or "localhost"
            rp_str = entry_rp.get().strip() or lp_str
            lbl_str = entry_lbl.get().strip() or f"Port {lp_str}"

            if not lp_str.isdigit() or not rp_str.isdigit():
                messagebox.showwarning("Input Error", "Port harus berupa angka valid (1 - 65535).", parent=dialog)
                return

            l_val = int(lp_str)
            r_val = int(rp_str)
            if not (1 <= l_val <= 65535) or not (1 <= r_val <= 65535):
                messagebox.showwarning("Input Error", "Nomor port harus berada dalam rentang 1 - 65535.", parent=dialog)
                return

            # Check duplicate Local Port with other rules
            for other_id in self.port_tree.get_children():
                if other_id != item_id:
                    other_vals = self.port_tree.item(other_id, "values")
                    if other_vals:
                        try:
                            if int(other_vals[1]) == l_val:
                                other_label = other_vals[3] or f"Port {l_val}"
                                messagebox.showwarning(
                                    "Port Bentrok",
                                    f"Local port {l_val} sudah digunakan oleh rule lain: '{other_label}'.\n"
                                    "Dua port forwarding lokal tidak dapat menggunakan nomor port yang sama.",
                                    parent=dialog
                                )
                                return
                        except (ValueError, IndexError):
                            pass

            new_enabled = enabled_var.get()
            enabled_badge = "✓ Enabled" if new_enabled else "✕ Disabled"

            curr_status = vals[4] if len(vals) > 4 else "○ Idle"
            if not new_enabled:
                curr_status = "Disabled"
            elif curr_status == "Disabled":
                curr_status = "○ Idle"

            self.port_tree.item(
                item_id,
                values=(enabled_badge, l_val, f"{rh_str}:{r_val}", lbl_str, curr_status)
            )

            self.update_command_preview()
            self.log(f"Rule port {l_val} berhasil diperbarui ({rh_str}:{r_val} - {lbl_str}).", "info")
            dialog.destroy()

            # Offer to restart forwarding if currently active
            if self.is_forwarding:
                should_restart = messagebox.askyesno(
                    "Restart Forwarding?",
                    "Port forwarding saat ini sedang berjalan.\n\n"
                    "Apakah Anda ingin me-restart port forwarding sekarang agar perubahan rule langsung diterapkan?"
                )
                if should_restart:
                    self.restart_forwarding()

        save_btn = tk.Button(btn_row, text="Save Changes", bg=self.accent_blue, fg="#0f172a",
                             font=("Segoe UI", 9, "bold"), command=save_edits, relief="flat", padx=14, pady=3)
        save_btn.pack(side=tk.RIGHT, padx=4)

        cancel_btn = tk.Button(btn_row, text="Cancel", bg=self.bg_input, fg=self.text_main,
                               font=("Segoe UI", 9), command=dialog.destroy, relief="flat", padx=10, pady=3)
        cancel_btn.pack(side=tk.RIGHT)

        entry_lp.bind("<Return>", lambda e: save_edits())
        entry_rh.bind("<Return>", lambda e: save_edits())
        entry_rp.bind("<Return>", lambda e: save_edits())
        entry_lbl.bind("<Return>", lambda e: save_edits())
        entry_lp.focus_set()

    def sort_tree_column(self, col):
        """Sorts the port Treeview by the clicked column and toggles ascending/descending."""
        if self.sort_state["col"] == col:
            reverse = not self.sort_state["reverse"]
        else:
            reverse = False
        self.sort_state["col"] = col
        self.sort_state["reverse"] = reverse

        items = self.port_tree.get_children("")
        if not items:
            return

        data = []
        for item_id in items:
            val = self.port_tree.set(item_id, col)
            if col == "local":
                try:
                    sort_key = int(val)
                except (ValueError, TypeError):
                    sort_key = 0
            elif col == "enabled":
                sort_key = 0 if "Enabled" in str(val) else 1
            elif col == "remote_target":
                try:
                    parts = str(val).rsplit(":", 1)
                    host = parts[0].lower()
                    port = int(parts[1]) if len(parts) > 1 else 0
                    sort_key = (host, port)
                except Exception:
                    sort_key = (str(val).lower(), 0)
            else:
                sort_key = str(val).lower()

            data.append((sort_key, item_id))

        data.sort(key=lambda t: t[0], reverse=reverse)

        for index, (_, item_id) in enumerate(data):
            self.port_tree.move(item_id, "", index)

        arrow = " ▼" if reverse else " ▲"
        for c, base_title in self.column_titles.items():
            if c == col:
                self.port_tree.heading(c, text=f"{base_title}{arrow}")
            else:
                self.port_tree.heading(c, text=base_title)

        self.update_command_preview()

    def on_rule_double_click(self, event):
        item = self.port_tree.identify_row(event.y)
        if item:
            self.port_tree.selection_set(item)
            self.root.after(10, self.edit_selected_rule)
        return "break"

    def on_f2_pressed(self, event=None):
        if self.port_tree.selection():
            self.edit_selected_rule()
            return "break"

    def on_toggle_rule_click(self, event):
        item = self.port_tree.identify_row(event.y)
        if item:
            self._toggle_rule(item)

    def toggle_selected_rules(self):
        for item in self.port_tree.selection():
            self._toggle_rule(item)

    def _toggle_rule(self, item_id):
        vals = list(self.port_tree.item(item_id, "values"))
        if not vals:
            return
        if "Enabled" in vals[0]:
            vals[0] = "✕ Disabled"
            vals[4] = "Disabled"
        else:
            vals[0] = "✓ Enabled"
            vals[4] = "○ Idle"
        self.port_tree.item(item_id, values=vals)
        self.update_command_preview()

    def delete_selected_rules(self):
        sel = self.port_tree.selection()
        for item in sel:
            self.port_tree.delete(item)
        self.update_command_preview()

    def clear_all_rules(self):
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        self.update_command_preview()

    def update_port_status(self, rule_id, status_text):
        def _do():
            if self.port_tree.exists(rule_id):
                vals = list(self.port_tree.item(rule_id, "values"))
                vals[4] = status_text
                self.port_tree.item(rule_id, values=vals)
        self.root.after(0, _do)

    def update_status_badge(self, text, status_type="idle"):
        def _do():
            colors = {
                "idle": ("#334155", "#cbd5e1"),
                "connecting": ("#b45309", "#fef3c7"),
                "active": ("#065f46", "#d1fae5"),
                "error": ("#991b1b", "#fee2e2")
            }
            bg, fg = colors.get(status_type, ("#334155", "#cbd5e1"))
            icon = "○" if status_type == "idle" else "●"
            self.status_badge.config(text=f"{icon} {text}", bg=bg, fg=fg)
        self.root.after(0, _do)

    def get_rules_list(self):
        rules = []
        for item_id in self.port_tree.get_children():
            vals = self.port_tree.item(item_id, "values")
            enabled = "Enabled" in vals[0]
            local_p = int(vals[1])
            rem_parts = str(vals[2]).split(":")
            rem_host = rem_parts[0] if len(rem_parts) > 1 else "localhost"
            rem_p = int(rem_parts[1]) if len(rem_parts) > 1 else int(vals[1])
            label = str(vals[3])

            rules.append({
                "id": item_id,
                "enabled": enabled,
                "local_port": local_p,
                "remote_host": rem_host,
                "remote_port": rem_p,
                "label": label
            })
        return rules

    def build_ssh_command_tokens(self):
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()
        user = self.user_entry.get().strip()
        key_path = self.key_entry.get().strip()
        auth_type = self.auth_var.get()

        tokens = ["ssh", "-N"]

        for r in self.get_rules_list():
            if r["enabled"]:
                tokens.extend(["-L", f"{r['local_port']}:{r['remote_host']}:{r['remote_port']}"])

        if port and port != "22":
            tokens.extend(["-p", port])

        if auth_type == "key" and key_path:
            tokens.extend(["-i", key_path])

        if user and host:
            tokens.append(f"{user}@{host}")
        elif host:
            tokens.append(host)

        return tokens

    def update_command_preview(self):
        tokens = self.build_ssh_command_tokens()
        self.cmd_preview_var.set(" ".join(tokens))

    def copy_command_to_clipboard(self):
        cmd = self.cmd_preview_var.get()
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd)
        self.log(f"Perintah SSH disalin ke clipboard:\n{cmd}", "success")

    def open_import_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Import / Parse SSH Command")
        dialog.geometry("640x260")
        dialog.configure(bg=self.bg_card)
        dialog.transient(self.root)
        dialog.update_idletasks()
        try:
            dialog.grab_set()
        except tk.TclError:
            try:
                dialog.wait_visibility()
                dialog.grab_set()
            except tk.TclError:
                pass

        tk.Label(dialog, text="Paste SSH Command di sini:", bg=self.bg_card,
                 fg=self.text_main, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        tk.Label(dialog, text="Contoh: ssh -N -L 8002:localhost:8002 -L 5173:localhost:5173 -L 19000:localhost:19000 user@your-server-ip",
                 bg=self.bg_card, fg=self.text_muted, font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(0, 6))

        entry_text = tk.Text(dialog, bg=self.bg_input, fg=self.text_main, font=("Consolas", 10), height=4)
        entry_text.insert(tk.END, "ssh -N -L 8002:localhost:8002 -L 5173:localhost:5173 -L 19000:localhost:19000 user@your-server-ip")
        entry_text.pack(fill=tk.BOTH, expand=True, padx=14, pady=4)

        btn_row = tk.Frame(dialog, bg=self.bg_card)
        btn_row.pack(fill=tk.X, padx=14, pady=10)

        def do_import():
            cmd = entry_text.get("1.0", tk.END).strip()
            parsed = parse_ssh_command(cmd)
            if not parsed or not (parsed["host"] or parsed["ports"]):
                messagebox.showerror("Parse Error", "Gagal membaca format perintah SSH.")
                return

            if parsed["host"]:
                self.host_entry.delete(0, tk.END)
                self.host_entry.insert(0, parsed["host"])
            if parsed["user"]:
                self.user_entry.delete(0, tk.END)
                self.user_entry.insert(0, parsed["user"])
            if parsed["port"]:
                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, parsed["port"])
            if parsed["key_path"]:
                self.auth_var.set("key")
                self.on_auth_type_changed()
                self.key_entry.delete(0, tk.END)
                self.key_entry.insert(0, parsed["key_path"])

            if parsed["ports"]:
                self.clear_all_rules()
                for p in parsed["ports"]:
                    rule_id = str(self.next_port_id)
                    self.next_port_id += 1
                    self.port_tree.insert(
                        "",
                        tk.END,
                        iid=rule_id,
                        values=("✓ Enabled", p["local_port"], f"{p['remote_host']}:{p['remote_port']}", p["label"], "○ Idle")
                    )

            self.update_command_preview()
            dialog.destroy()
            self.log(f"Berhasil mengimpor {len(parsed['ports'])} port forwarding dari perintah SSH!", "success")

        tk.Button(btn_row, text="Import Now", bg=self.accent_blue, fg="#0f172a", font=("Segoe UI", 9, "bold"),
                  command=do_import, relief="flat", padx=10).pack(side=tk.RIGHT, padx=4)
        tk.Button(btn_row, text="Cancel", bg=self.bg_input, fg=self.text_main,
                  command=dialog.destroy, relief="flat", padx=10).pack(side=tk.RIGHT)

    # ==========================
    # Forwarding Controls
    # ==========================
    def toggle_forwarding(self):
        if self.is_forwarding:
            self.stop_forwarding()
        else:
            self.start_forwarding()

    def test_ssh_connection(self):
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()
        user = self.user_entry.get().strip()
        auth_type = self.auth_var.get()
        pwd = self.pwd_entry.get()
        key_p = self.key_entry.get().strip()

        if not host or not user:
            messagebox.showwarning("Incomplete", "Harap isi Host dan Username terlebih dahulu.")
            return

        self.test_btn.config(state=tk.DISABLED, text="Testing...")

        def _worker():
            try:
                tester = ParamikoForwarder(self.log, lambda s, t: None, lambda i, s: None)
                tester.connect(host, port, user, auth_type, pwd, key_p)
                tester.stop()
                success_msg = f"Koneksi ke {user}@{host}:{port} berhasil!"
                self.root.after(0, lambda m=success_msg: messagebox.showinfo("Connection Success", m))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda m=err_msg: messagebox.showerror("Connection Failed", f"Gagal terhubung:\n{m}"))
            finally:
                self.root.after(0, lambda: self.test_btn.config(state=tk.NORMAL, text="Test Connection"))

        threading.Thread(target=_worker, daemon=True).start()

    def start_forwarding(self):
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip() or "22"
        user = self.user_entry.get().strip()
        auth_type = self.auth_var.get()
        password = self.pwd_entry.get()
        key_path = self.key_entry.get().strip()
        engine = self.engine_var.get()
        rules = self.get_rules_list()

        enabled_rules = [r for r in rules if r["enabled"]]
        if not enabled_rules:
            messagebox.showwarning("No Ports", "Tidak ada port forwarding yang diaktifkan.")
            return

        if not host:
            messagebox.showwarning("Host Kosong", "Harap masukkan Host / IP SSH server.")
            return

        self.is_forwarding = True
        self.action_btn.config(text="■ STOP FORWARDING", bg=self.accent_red)
        self.update_status_badge("Starting...", "connecting")

        def _worker():
            try:
                if engine == "paramiko":
                    self.paramiko_engine.connect(host, port, user, auth_type, password, key_path)
                    self.paramiko_engine.start_tunnels(enabled_rules)
                else:
                    cmd_tokens = self.build_ssh_command_tokens()
                    self.openssh_engine.start(cmd_tokens)
            except Exception as e:
                err_msg = str(e)
                self.log(f"Error memulai forwarding: {err_msg}", "error")
                self.root.after(0, self.stop_forwarding)
                self.root.after(0, lambda m=err_msg: messagebox.showerror("Forwarding Error", m))

        threading.Thread(target=_worker, daemon=True).start()

    def stop_forwarding(self):
        self.is_forwarding = False
        self.action_btn.config(text="▶ START FORWARDING", bg=self.accent_green)
        self.update_status_badge("Stopped", "idle")

        def _stop_worker():
            try:
                self.paramiko_engine.stop()
                self.openssh_engine.stop()
            except Exception:
                pass
            for r in self.get_rules_list():
                self.update_port_status(r["id"], "○ Idle" if r["enabled"] else "Disabled")
            self.log("Port forwarding dihentikan.", "info")

        threading.Thread(target=_stop_worker, daemon=True).start()

    def restart_forwarding(self):
        """Stops current port forwarding and restarts it with updated rules."""
        self.log("Memulai ulang port forwarding dengan aturan yang diperbarui...", "info")
        self.stop_forwarding()
        self.root.after(800, self.start_forwarding)

    # ==========================
    # Logging
    # ==========================
    def log(self, message, tag="info"):
        def _do():
            self.log_text.config(state=tk.NORMAL)
            timestamp = time.strftime("[%H:%M:%S] ")
            self.log_text.insert(tk.END, timestamp, "time")
            self.log_text.insert(tk.END, message + "\n", tag)
            self.log_text.config(state=tk.DISABLED)
            if self.autoscroll_var.get():
                self.log_text.see(tk.END)
        self.root.after(0, _do)

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    # ==========================
    # Profiles & Persistence
    # ==========================
    def load_profiles(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    self.profiles = data.get("profiles", DEFAULT_PROFILES)
                    self.current_profile_key = data.get("current_profile", "default")
            except Exception as e:
                print(f"Error loading config: {e}")
                self.profiles = DEFAULT_PROFILES
        else:
            self.profiles = DEFAULT_PROFILES

        self.update_profile_dropdown()

    def save_all_config(self):
        self.save_current_profile(silent=True)
        config_data = {
            "current_profile": self.current_profile_key,
            "profiles": self.profiles
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")

    def update_profile_dropdown(self):
        keys = list(self.profiles.keys())
        self.profile_combo["values"] = keys
        if self.current_profile_key in keys:
            self.profile_combo.set(self.current_profile_key)
        elif keys:
            self.current_profile_key = keys[0]
            self.profile_combo.set(keys[0])

    def on_profile_change(self, event=None):
        selected = self.profile_combo.get()
        if selected in self.profiles:
            self.apply_profile(selected)

    def apply_profile(self, profile_key):
        self.current_profile_key = profile_key
        prof = self.profiles.get(profile_key, {})

        self.host_entry.delete(0, tk.END)
        self.host_entry.insert(0, prof.get("host", ""))

        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(prof.get("port", "22")))

        self.user_entry.delete(0, tk.END)
        self.user_entry.insert(0, prof.get("user", ""))

        auth_t = prof.get("auth_type", "password")
        self.auth_var.set(auth_t)
        self.on_auth_type_changed()

        self.pwd_entry.delete(0, tk.END)
        if prof.get("save_password", False):
            self.pwd_entry.insert(0, prof.get("password", ""))

        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, prof.get("key_path", ""))

        self.engine_var.set(prof.get("engine", "paramiko"))

        self.clear_all_rules()
        ports_list = prof.get("ports", [])
        for p in ports_list:
            rule_id = str(self.next_port_id)
            self.next_port_id += 1
            enabled_txt = "✓ Enabled" if p.get("enabled", True) else "✕ Disabled"
            self.port_tree.insert(
                "",
                tk.END,
                iid=rule_id,
                values=(
                    enabled_txt,
                    p.get("local_port", 0),
                    f"{p.get('remote_host', 'localhost')}:{p.get('remote_port', 0)}",
                    p.get("label", ""),
                    "○ Idle" if p.get("enabled", True) else "Disabled"
                )
            )

        self.update_command_preview()

    def save_current_profile(self, silent=False):
        prof = {
            "name": self.current_profile_key,
            "host": self.host_entry.get().strip(),
            "port": self.port_entry.get().strip(),
            "user": self.user_entry.get().strip(),
            "auth_type": self.auth_var.get(),
            "key_path": self.key_entry.get().strip(),
            "save_password": True,
            "password": self.pwd_entry.get(),
            "engine": self.engine_var.get(),
            "ports": self.get_rules_list()
        }
        self.profiles[self.current_profile_key] = prof
        if not silent:
            self.save_all_config()
            self.log(f"Profile '{self.current_profile_key}' berhasil disimpan ke {CONFIG_FILE}.", "success")

    def create_new_profile_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("New Profile")
        dialog.geometry("340x140")
        dialog.configure(bg=self.bg_card)
        dialog.transient(self.root)
        dialog.update_idletasks()
        try:
            dialog.grab_set()
        except tk.TclError:
            try:
                dialog.wait_visibility()
                dialog.grab_set()
            except tk.TclError:
                pass

        tk.Label(dialog, text="Nama Profile Baru:", bg=self.bg_card, fg=self.text_main,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(14, 4))
        name_entry = ttk.Entry(dialog, width=28)
        name_entry.pack(fill=tk.X, padx=14, pady=4)
        name_entry.focus_set()

        def do_create():
            n = name_entry.get().strip()
            if not n:
                return
            if n in self.profiles:
                messagebox.showerror("Error", "Nama profile sudah ada.")
                return
            self.profiles[n] = {
                "name": n,
                "host": self.host_entry.get().strip(),
                "port": self.port_entry.get().strip(),
                "user": self.user_entry.get().strip(),
                "auth_type": self.auth_var.get(),
                "key_path": self.key_entry.get().strip(),
                "password": self.pwd_entry.get(),
                "save_password": True,
                "engine": self.engine_var.get(),
                "ports": self.get_rules_list()
            }
            self.current_profile_key = n
            self.update_profile_dropdown()
            self.save_all_config()
            dialog.destroy()
            self.log(f"Profile baru '{n}' berhasil dibuat.", "success")

        btn_row = tk.Frame(dialog, bg=self.bg_card)
        btn_row.pack(fill=tk.X, padx=14, pady=10)
        tk.Button(btn_row, text="Create", bg=self.accent_blue, fg="#0f172a", font=("Segoe UI", 9, "bold"),
                  command=do_create, relief="flat", padx=10).pack(side=tk.RIGHT, padx=4)
        tk.Button(btn_row, text="Cancel", bg=self.bg_input, fg=self.text_main,
                  command=dialog.destroy, relief="flat", padx=10).pack(side=tk.RIGHT)

    def on_close(self):
        try:
            self.save_all_config()
            if self.is_forwarding:
                self.paramiko_engine.stop()
                self.openssh_engine.stop()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = SSHMultiPortForwarderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
