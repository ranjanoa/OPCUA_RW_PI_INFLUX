import asyncio
import threading
import time
import csv
import os
import pathlib
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from cryptography.hazmat.backends import default_backend
from asyncua import Client
from asyncua.crypto.security_policies import (
    SecurityPolicyBasic128Rsa15,
    SecurityPolicyBasic256,
    SecurityPolicyBasic256Sha256
)
from asyncua import ua
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from asyncua.ua.uaerrors import BadSessionIdInvalid
from datetime import datetime

# InfluxDB 2.7
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# FastAPI for OPC Write API
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from typing import Union  # For API types


class WriteRequest(BaseModel):
    node_id: str
    value: str | float | int | bool

app_api = FastAPI(title="OPC UA Write API")

class OpcUaArchiverApp(tk.Tk):
    POLL_INTERVAL_MS = 30000
    RECONNECT_INTERVAL_SEC = 60

    def __init__(self):
        super().__init__()
        self.title("Data@Glance OPC UA Archiver v2.7")
        self.geometry("1200x1000")

        # Manual tags file
        default_file = "manual_tags.csv"
        user_file = simpledialog.askstring("Manual Tags", "Filename for manual tags:", initialvalue=default_file)
        self.manual_tags_file = user_file.strip() if user_file else default_file

        # InfluxDB defaults
        self.influx_host = "localhost"
        self.influx_port = 8086
        self.influx_token = ""
        self.influx_org = "your-org"
        self.influx_bucket = "opcua_data"

        # Certs
        self.cert_folder = pathlib.Path("./certificates")
        self.cert_folder.mkdir(exist_ok=True)
        self.client_cert_path = self.cert_folder / "client_cert.der"
        self.client_key_path = self.cert_folder / "client_key.pem"
        self.server_cert_path = self.cert_folder / "server_cert.der"

        self.stored_url = ""
        self.archiving_event = threading.Event()
        self.archiving = False
        self.client = None
        self.influx_client = None
        self.manual_tags = {}
        self._last_update_times = {}
        self._update_intervals = {}
        self._auto_refresh_running = False
        self.stop_reconnect = threading.Event()

        self._start_async_loop()
        self._build_ui()
        self.load_config()
        self.load_manual_tags()
        self.after(1000, self.establish_final_connection)

        # Start API server
        threading.Thread(target=self.start_api_server, daemon=True).start()

    def _start_async_loop(self):
        def run_loop(loop):
            asyncio.set_event_loop(loop)
            loop.run_forever()
        self.async_loop = asyncio.new_event_loop()
        threading.Thread(target=run_loop, args=(self.async_loop,), daemon=True).start()

    def _run_async_threadsafe(self, coro):
        future = asyncio.run_coroutine_threadsafe(coro, self.async_loop)
        return future.result()

    def _build_ui(self):
        # Row 0: OPC UA Connection
        tk.Label(self, text="Server URL:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.entry_url = tk.Entry(self, width=25)
        self.entry_url.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        self.entry_url.insert(0, "opc.tcp://innm5cg44629dm:57888/OpcExpert")

        tk.Label(self, text="Username:").grid(row=0, column=2, sticky="w", padx=5, pady=2)
        self.entry_username = tk.Entry(self, width=15)
        self.entry_username.grid(row=0, column=3, sticky="ew", padx=5, pady=2)

        tk.Label(self, text="Password:").grid(row=0, column=4, sticky="w", padx=5, pady=2)
        self.entry_password = tk.Entry(self, show="*", width=15)
        self.entry_password.grid(row=0, column=5, sticky="ew", padx=5, pady=2)

        self.btn_connect = tk.Button(self, text="Connect", command=self.establish_final_connection)
        self.btn_connect.grid(row=0, column=6, padx=5, pady=2)
        self.btn_disconnect = tk.Button(self, text="Disconnect", command=self.disconnect, state="disabled")
        self.btn_disconnect.grid(row=0, column=7, padx=5, pady=2)

        # Row 1: InfluxDB 2.7 Credentials
        tk.Label(self, text="Influx Token:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.entry_influx_token = tk.Entry(self, show="*", width=30)
        self.entry_influx_token.grid(row=1, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        tk.Label(self, text="Org:").grid(row=1, column=3, sticky="w", padx=5, pady=2)
        self.entry_influx_org = tk.Entry(self, width=12)
        self.entry_influx_org.grid(row=1, column=4, sticky="ew", padx=5, pady=2)
        self.entry_influx_org.insert(0, "your-org")

        tk.Label(self, text="Bucket:").grid(row=1, column=5, sticky="w", padx=5, pady=2)
        self.entry_influx_bucket = tk.Entry(self, width=12)
        self.entry_influx_bucket.grid(row=1, column=6, sticky="ew", padx=5, pady=2)
        self.entry_influx_bucket.insert(0, "opcua_data")

        self.btn_save_influx = tk.Button(self, text="Save Influx", command=self.save_influx_config)
        self.btn_save_influx.grid(row=1, column=7, padx=5, pady=2)

        # Row 2: Controls
        self.btn_load_tree = tk.Button(self, text="Load Browse Tree", command=self.load_tree_thread, state="disabled")
        self.btn_load_tree.grid(row=2, column=6, padx=5, pady=2)

        # Treeview
        self.tree = ttk.Treeview(self)
        self.tree.heading("#0", text="OPC UA Tags")
        self.tree.grid(row=3, column=0, columnspan=8, sticky="nsew", padx=5, pady=2)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        scrollbar_tree = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        scrollbar_tree.grid(row=3, column=8, sticky="ns", pady=2)
        self.tree.configure(yscrollcommand=scrollbar_tree.set)

        # Manual tags frame
        frame_manual = ttk.Frame(self)
        frame_manual.grid(row=4, column=0, columnspan=8, sticky="ew", padx=5, pady=2)
        tk.Label(frame_manual, text="Tag:").pack(side="left", padx=2)
        self.entry_manual_name = tk.Entry(frame_manual, width=20)
        self.entry_manual_name.pack(side="left", padx=2)
        tk.Label(frame_manual, text="NodeId:").pack(side="left", padx=2)
        self.entry_manual_nodeid = tk.Entry(frame_manual, width=40)
        self.entry_manual_nodeid.pack(side="left", padx=2)
        tk.Button(frame_manual, text="Add", command=self.add_manual_tag).pack(side="left", padx=2)

        # Manual table
        self.manual_table = ttk.Treeview(self, columns=("TagName", "NodeId", "LastValue", "LastTimestamp", "UpdateRate"), show="headings")
        self.manual_table.heading("TagName", text="Tag")
        self.manual_table.heading("NodeId", text="NodeId")
        self.manual_table.heading("LastValue", text="Value")
        self.manual_table.heading("LastTimestamp", text="Time")
        self.manual_table.heading("UpdateRate", text="Rate(s)")
        self.manual_table.grid(row=5, column=0, columnspan=8, sticky="nsew", padx=5, pady=2)
        self.manual_table.bind("<<TreeviewSelect>>", self.on_manual_table_select)
        scrollbar_manual = ttk.Scrollbar(self, orient="vertical", command=self.manual_table.yview)
        scrollbar_manual.grid(row=5, column=8, sticky="ns", pady=2)
        self.manual_table.configure(yscrollcommand=scrollbar_manual.set)

        self.btn_remove_manual_tag = tk.Button(self, text="Remove Selected", command=self.remove_manual_tag, state="disabled")
        self.btn_remove_manual_tag.grid(row=6, column=0, padx=5, pady=2)

        # Archiving
        tk.Label(self, text="Interval(s):").grid(row=6, column=1, sticky="w", padx=5, pady=2)
        self.entry_archive_interval = tk.Entry(self, width=8)
        self.entry_archive_interval.insert(0, "1")
        self.entry_archive_interval.grid(row=6, column=2, sticky="ew", padx=5, pady=2)

        self.btn_start_archive = tk.Button(self, text="Start Archive", command=self.start_combined_loop, state="disabled")
        self.btn_start_archive.grid(row=6, column=3, padx=5, pady=2)
        self.btn_stop_archive = tk.Button(self, text="Stop Archive", command=self.stop_archiving, state="disabled")
        self.btn_stop_archive.grid(row=6, column=4, padx=5, pady=2)

        # Write API test
        tk.Button(self, text="Test API: POST /write", command=self.test_api_write).grid(row=6, column=5, padx=5, pady=2)
        self.lbl_status = tk.Label(self, text="Status: Ready")
        self.lbl_status.grid(row=7, column=0, columnspan=8, sticky="w", padx=5, pady=2)

        # Configure grid
        for col in range(9):
            self.columnconfigure(col, weight=1 if col < 8 else 0)
        self.rowconfigure(3, weight=1)
        self.rowconfigure(5, weight=1)

    def show_message(self, msg):
        self.lbl_status.config(text=msg[-100:])  # Truncate status
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def save_influx_config(self):
        self.influx_token = self.entry_influx_token.get()
        self.influx_org = self.entry_influx_org.get()
        self.influx_bucket = self.entry_influx_bucket.get()
        config = self.get_config()
        with open("config.json", "w") as f:
            json.dump(config, f)
        self.show_message("Influx config saved")

    def get_config(self):
        return {
            "url": self.entry_url.get(),
            "username": self.entry_username.get(),
            "password": self.entry_password.get(),
            "influx_token": self.influx_token,
            "influx_org": self.influx_org,
            "influx_bucket": self.influx_bucket
        }

    def load_config(self):
        if os.path.exists("config.json"):
            try:
                with open("config.json") as f:
                    data = json.load(f)
                self.entry_url.delete(0, tk.END); self.entry_url.insert(0, data.get("url", ""))
                self.entry_username.delete(0, tk.END); self.entry_username.insert(0, data.get("username", ""))
                self.entry_password.delete(0, tk.END); self.entry_password.insert(0, data.get("password", ""))
                self.entry_influx_token.delete(0, tk.END); self.entry_influx_token.insert(0, data.get("influx_token", ""))
                self.entry_influx_org.delete(0, tk.END); self.entry_influx_org.insert(0, data.get("influx_org", "your-org"))
                self.entry_influx_bucket.delete(0, tk.END); self.entry_influx_bucket.insert(0, data.get("influx_bucket", "opcua_data"))
                self.influx_token = data.get("influx_token", "")
                self.show_message("Config loaded")
            except Exception as e:
                self.show_message(f"Config error: {e}")

    # Connection methods (your originals, abbreviated for space)
    def establish_final_connection(self):
        self.save_influx_config()
        def thread_connect():
            try:
                async def async_connect():
                    client = Client(self.entry_url.get())
                    client.application_name = "Data@Glance OPC UA Archiver"
                    
                    policies = [
                        SecurityPolicyBasic256Sha256,
                        SecurityPolicyBasic256,
                        SecurityPolicyBasic128Rsa15
                    ]
                    
                    connected_with_security = False
                    for policy in policies:
                        for mode in [ua.MessageSecurityMode.SignAndEncrypt, ua.MessageSecurityMode.Sign]:
                            try:
                                await client.set_security(
                                    policy,
                                    certificate=str(self.client_cert_path),
                                    private_key=str(self.client_key_path),
                                    mode=mode
                                )
                                connected_with_security = True
                                self.show_message(f"Security: {policy.__name__} ({mode.name})")
                                break
                            except Exception:
                                continue
                        if connected_with_security:
                            break
                    
                    if not connected_with_security:
                        self.show_message("Cert security failed, connecting without cert")
                    
                    username = self.entry_username.get()
                    password = self.entry_password.get()
                    if username: client.set_user(username)
                    if password: client.set_password(password)
                    
                    await asyncio.wait_for(client.connect(), timeout=10.0)  # 10s timeout
                    return client

                self.client = self._run_async_threadsafe(async_connect())
                self.after(0, self.post_connection_setup)
            except asyncio.TimeoutError:
                self.show_message("Connection timeout - check URL/server")
            except Exception as e:
                self.show_message(f"Connect failed: {str(e)[:100]}")
                self.after(0, self.start_reconnect_loop)
            finally:
                self.after(0, lambda: self.btn_connect.config(state="normal"))
        
        self.btn_connect.config(state="disabled")
        threading.Thread(target=thread_connect, daemon=True).start()

    def post_connection_setup(self):
        self.show_message("Connected ✓ API: http://localhost:8000/write")
        self.btn_disconnect.config(state="normal")
        self.btn_load_tree.config(state="normal")
        self.btn_start_archive.config(state="normal" if self.manual_tags else "disabled")
        self.update_manual_ui()
        self.load_manual_tags()

    def disconnect(self):
        self.archiving_event.set()
        if self.client:
            try:
                self.client.disconnect()  # Sync disconnect
            except:
                pass
            self.client = None
        self.show_message("Disconnected")
        self.btn_connect.config(state="normal")
        self.btn_disconnect.config(state="disabled")
        self.btn_load_tree.config(state="disabled")
        self.btn_start_archive.config(state="disabled")

    def start_reconnect_loop(self):
        """Start background reconnect attempts"""
        if hasattr(self, 'reconnect_thread') and self.reconnect_thread.is_alive():
            return
        self.stop_reconnect.clear()
        self.reconnect_thread = threading.Thread(target=self._reconnect_loop, daemon=True)
        self.reconnect_thread.start()

    def _reconnect_loop(self):
        """Reconnect loop"""
        while not self.stop_reconnect.is_set():
            try:
                self.show_message("Reconnecting...")
                self.establish_final_connection()
                break
            except:
                pass
            time.sleep(self.RECONNECT_INTERVAL_SEC)


    # Tree & Manual tags (your logic + auto-add)
    def load_tree_thread(self):
        threading.Thread(target=self.load_tree, daemon=True).start()

    def load_tree(self):
        if not self.client: return
        self.tree.delete(*self.tree.get_children())
        try:
            async def populate():
                root = self.client.nodes.root
                objs = await root.get_child(["0:Objects"])
                await self._populate_tree(objs, "")
            self._run_async_threadsafe(populate())
            self.show_message("Tree loaded")
        except Exception as e:
            self.show_message(f"Tree error: {e}")

    async def _populate_tree(self, node, parent):
        children = await node.get_children()
        for child in children:
            display = (await child.read_display_name()).Text
            nodeid = child.nodeid.to_string()
            self.tree.insert(parent, "end", text=display, values=(nodeid,))
            await self._populate_tree(child, self.tree.get_children(parent)[-1])

    def on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        tag_name = self.tree.item(sel[0])["text"]
        nodeid = self.tree.item(sel[0])["values"][0]
        if tag_name not in self.manual_tags:
            self.manual_tags[tag_name] = nodeid
            self.manual_table.insert("", "end", iid=tag_name, values=(tag_name, nodeid, "N/A", "", ""))
            self.save_manual_tags()
            self.update_manual_ui()
            self.show_message(f"✓ Added '{tag_name}'")

    def add_manual_tag(self):
        tag = self.entry_manual_name.get().strip()
        nid = self.entry_manual_nodeid.get().strip()
        if tag and nid and tag not in self.manual_tags:
            self.manual_tags[tag] = nid
            self.manual_table.insert("", "end", iid=tag, values=(tag, nid, "N/A", "", ""))
            self.save_manual_tags()
            self.update_manual_ui()
            self.show_message(f"✓ Added manual '{tag}'")

    def remove_manual_tag(self):
        sel = self.manual_table.selection()
        if sel and messagebox.askyesno("Confirm", f"Remove {sel[0]}?"):
            self.manual_tags.pop(sel[0], None)
            self.manual_table.delete(sel[0])
            self.save_manual_tags()
            self.update_manual_ui()

    def update_manual_ui(self):
        tags = list(self.manual_tags)
        self.btn_start_archive.config(state="normal" if tags else "disabled")
        self.btn_remove_manual_tag.config(state="normal" if self.manual_table.selection() else "disabled")


    def on_manual_table_select(self, event):
        """Enable remove button on table selection"""
        selection = self.manual_table.selection()
        self.btn_remove_manual_tag.config(state="normal" if selection else "disabled")
    

    def save_manual_tags(self):
        with open(self.manual_tags_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["TagName", "NodeId"])
            for tag, nid in self.manual_tags.items():
                writer.writerow([tag, nid])

    def load_manual_tags(self):
        self.manual_tags.clear()
        self.manual_table.delete(*self.manual_table.get_children())
        if os.path.exists(self.manual_tags_file):
            with open(self.manual_tags_file) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    tag, nid = row["TagName"], row["NodeId"]
                    self.manual_tags[tag] = nid
                    self.manual_table.insert("", "end", iid=tag, values=(tag, nid, "N/A", "", ""))
        self.update_manual_ui()

    # Combined archiving + refresh
    async def read_all_tags_batch(self, tag_map):
        nodes = [self.client.get_node(nid) for nid in tag_map.values()]
        return dict(zip(tag_map, await self.client.read_values(nodes)))

    def start_combined_loop(self):
        interval = float(self.entry_archive_interval.get() or 1)
        self.archiving_event.clear()
        self.archiving = True
        self.btn_start_archive.config(state="disabled")
        self.btn_stop_archive.config(state="normal")
        threading.Thread(target=self._combined_loop, args=(interval,), daemon=True).start()
        self.show_message("Archiving started")

    def _combined_loop(self, interval):
        write_api = None
        try:
            self.influx_client = InfluxDBClient(url=f"http://{self.influx_host}:{self.influx_port}",
                                              token=self.influx_token, org=self.influx_org)
            write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)
            measurement = f"opcua_{int(interval)}s"

            while not self.archiving_event.is_set():
                start = time.time()
                try:
                    tag_values = self._run_async_threadsafe(self.read_all_tags_batch(self.manual_tags))
                    
                    # InfluxDB 2.7 batch write
                    points = []
                    now_ns = int(time.time() * 1e9)
                    for tag, val in tag_values.items():
                        field_val = float(val) if isinstance(val, (int, float)) else str(val)
                        points.append(Point(measurement).field(tag, field_val).time(now_ns))
                    
                    if points:
                        write_api.write(bucket=self.influx_bucket, record=points)
                    
                    # Update rates/timings
                    now = datetime.now()
                    for tag in tag_values:
                        last = self._last_update_times.get(tag)
                        if last:
                            elapsed = (now - last).total_seconds()
                            prev = self._update_intervals.get(tag, elapsed)
                            self._update_intervals[tag] = (prev + elapsed) / 2
                        self._last_update_times[tag] = now

                    # UI update
                    def update_ui():
                        for tag, val in tag_values.items():
                            ts = self._last_update_times.get(tag)
                            rate = self._update_intervals.get(tag, 0)
                            self.manual_table.set(tag, "LastValue", str(val))
                            self.manual_table.set(tag, "LastTimestamp", ts.strftime("%H:%M:%S") if ts else "")
                            self.manual_table.set(tag, "UpdateRate", f"{rate:.1f}")
                    self.after(0, update_ui)
                    self.show_message(f"Wrote {len(points)} pts @ {interval}s")

                except Exception as e:
                    self.show_message(f"Loop error: {e}")
                
                time.sleep(max(0, interval - (time.time() - start)))
        except Exception as e:
            self.show_message(f"Archive error: {e}")
        finally:
            if self.influx_client:
                self.influx_client.close()

    def stop_archiving(self):
        self.archiving_event.set()
        self.archiving = False
        self.btn_start_archive.config(state="normal")
        self.btn_stop_archive.config(state="disabled")
        self.show_message("Archiving stopped")

    # API methods
    def start_api_server(self):
        @app_api.post("/write")
        async def opc_write(request: WriteRequest):
            if not self.client:
                raise HTTPException(503, "Not connected")
            try:
                node = self.client.get_node(request.node_id)
                await node.write_value(request.value)
                return {"status": "ok", "node": request.node_id, "value": request.value}
            except Exception as e:
                raise HTTPException(500, str(e))
        
        uvicorn.run(app_api, host="0.0.0.0", port=8000, log_level="error")

    def test_api_write(self):
        self.show_message("API test: curl -X POST http://localhost:8000/write -d '{\"node_id\":\"ns=2;s=test\",\"value\":123}'")

if __name__ == "__main__":
    app = OpcUaArchiverApp()
    app.mainloop()
