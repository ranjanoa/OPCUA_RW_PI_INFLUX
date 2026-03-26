import sys
import os
import asyncio
# VERSION 4.2 (Complete, Un-truncated, Fully Integrated)
import logging
import json
import csv
import time
import re
from datetime import datetime, timezone
from collections import deque

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QListWidget, QListWidgetItem,
    QPlainTextEdit, QLabel, QLineEdit, QSplitter, QGroupBox,
    QDialog, QTreeWidget, QTreeWidgetItem, QMessageBox, QStatusBar,
    QTextBrowser, QComboBox, QCheckBox, QDialogButtonBox, QFormLayout,
    QRadioButton, QSpinBox, QTreeWidgetItemIterator, QAbstractItemView,
    QMenu, QScrollArea
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, pyqtSlot
from PyQt6.QtGui import QIcon, QColor, QAction

# Import OPC UA and InfluxDB
from asyncua import Client, ua
from asyncua.crypto.security_policies import (
    SecurityPolicyBasic128Rsa15,
    SecurityPolicyBasic256,
    SecurityPolicyBasic256Sha256
)
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS, ASYNCHRONOUS

from cryptography.hazmat.backends import default_backend
from cryptography import x509
import pathlib

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import qasync
import requests
import threading
requests.packages.urllib3.disable_warnings()

class WriteRequest(BaseModel):
    node_id: str
    value: str | float | int | bool

async def setup_opc_security(client, opc_config):
    client.application_name = "Data@Glance OPC UA Archiver"
    cert_path = opc_config.get('cert_path')
    key_path = opc_config.get('key_path')
    username = opc_config.get('username')
    password = opc_config.get('password')
    use_cert = opc_config.get('use_cert_security', False)

    if use_cert and cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
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
                        certificate=cert_path,
                        private_key=key_path,
                        mode=mode
                    )
                    connected_with_security = True
                    logging.info(f"Set security to {policy.__name__} in mode {mode.name}")
                    break
                except Exception as e:
                    continue
            if connected_with_security:
                break
        
        if not connected_with_security:
            logging.warning("All cert security policies failed, connecting without cert")

    if username: client.set_user(username)
    if password: client.set_password(password)


# --- CONFIGURATION ---
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".opc_influx_client_selections.json")
ICON_FILE = 'app_icon.ico'

try:
    import config
except ImportError:
    config = None


# --- CUSTOM LOGGER ---
class QtLogHandler(logging.Handler):
    def __init__(self, log_signal):
        super().__init__()
        self.log_signal = log_signal

    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)


# --- CONFIG EDITOR ---
class ConfigEditorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("System Configuration (config.py)")
        self.setMinimumSize(500, 400)
        self.layout = QVBoxLayout(self)

        form_group = QGroupBox("Edit Configuration File")
        self.form_layout = QFormLayout()
        self.fields = {}
        self.config_map = {
            "DB_URL": "Influx URL", "DB_TOKEN": "Influx Token", "DB_ORG": "Organization",
            "DB_BUCKET": "Bucket Name", 
            "DB_MEASUREMENT_OPC": "OPC Measurement",
            "DB_MEASUREMENT_PI": "PI Measurement",
            "DB_MEASUREMENT_SETPOINTS": "Write-Back Measurement"
        }

        self._load_current_config()
        form_group.setLayout(self.form_layout)
        self.layout.addWidget(form_group)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save_config)
        buttons.rejected.connect(self.reject)
        self.layout.addWidget(buttons)

    def _load_current_config(self):
        if not os.path.exists('config.py'): return
        try:
            with open('config.py', 'r') as f:
                content = f.read()
            for var_name, label in self.config_map.items():
                match = re.search(rf'{var_name}\s*=\s*["\'](.*?)["\']', content)
                val = match.group(1) if match else ""
                line_edit = QLineEdit(str(val))
                if "TOKEN" in var_name: line_edit.setEchoMode(QLineEdit.EchoMode.Password)
                self.form_layout.addRow(label + ":", line_edit)
                self.fields[var_name] = line_edit
        except Exception as e:
            QMessageBox.critical(self, "Config Error", str(e))

    def _save_config(self):
        if not os.path.exists('config.py'): return
        try:
            with open('config.py', 'r') as f:
                content = f.read()
            for var_name, line_edit in self.fields.items():
                content = re.sub(rf'({var_name}\s*=\s*)(["\'])(.*?)(["\'])', rf'\1\2{line_edit.text()}\4', content)
            with open('config.py', 'w') as f:
                f.write(content)
            QMessageBox.information(self, "Success", "Configuration saved.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))


# --- SERVER BROWSER ---
class ServerBrowseDialog(QDialog):
    tags_selected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("OPC UA Server Browser")
        self.setMinimumSize(800, 700)
        self.layout = QVBoxLayout(self)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Node Name", "NodeID", "Type", "Value"])
        self.tree.setColumnWidth(0, 300)
        self.layout.addWidget(self.tree)
        self.tree.itemExpanded.connect(self.on_item_expanded)
        self.client = None
        self.browse_path = ""

        btn_layout = QHBoxLayout()
        self.select_button = QPushButton("Add Selected Tags")
        self.select_button.clicked.connect(self._add_selected_tags)
        btn_layout.addWidget(self.select_button)
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        btn_layout.addWidget(self.close_button)
        self.layout.addLayout(btn_layout)
        self.selected_node_ids = set()

    async def populate_tree(self, client, existing_selections_nodeids=None, browse_path=""):
        self.client = client
        self.tree.clear()
        self.selected_node_ids.clear()
        self.browse_path = browse_path
        if existing_selections_nodeids:
            self.selected_node_ids.update(existing_selections_nodeids)
        try:
            target_node = client.get_objects_node()
            if self.browse_path:
                parts = [p.strip() for p in self.browse_path.split("/") if p.strip()]
                for part in parts:
                    try:
                        target_node = await target_node.get_child([part])
                    except:
                        logging.warning(f"Browser: Path part '{part}' not found")
                        break
            
            node_id = target_node.nodeid.to_string()
            display = (await target_node.read_display_name()).Text
            node_class = await target_node.read_node_class()
            
            root_item = QTreeWidgetItem(self.tree, [display, node_id, node_class.name, ""])
            if node_class == ua.NodeClass.Object:
                QTreeWidgetItem(root_item, ["loading..."])
            root_item.setExpanded(False)
        except Exception as e:
            logging.error(f"Browser Error: {e}")

    def on_item_expanded(self, item):
        if item.childCount() == 1 and item.child(0).text(0) == "loading...":
            item.removeChild(item.child(0))
            node_id = item.text(1)
            asyncio.create_task(self._add_children_to_tree(self.client, node_id, item))

    async def _add_children_to_tree(self, client, node_id, parent_item):
        try:
            parent_node = client.get_node(node_id)
            children = await parent_node.get_children()
            for child in children:
                display_name = await child.read_display_name()
                child_node_id = child.nodeid.to_string()
                node_class = await child.read_node_class()

                item = QTreeWidgetItem(parent_item, [display_name.Text, child_node_id, node_class.name, ""])
                if node_class == ua.NodeClass.Variable:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(0,
                                       Qt.CheckState.Checked if child_node_id in self.selected_node_ids else Qt.CheckState.Unchecked)
                elif node_class == ua.NodeClass.Object:
                    QTreeWidgetItem(item, ["loading..."])
        except Exception as e:
            logging.error(f"Error loading children for {node_id}: {e}")

    def _add_selected_tags(self):
        selected = {}
        iterator = QTreeWidgetItemIterator(self.tree)
        while iterator.value():
            item = iterator.value()
            if item.checkState(0) == Qt.CheckState.Checked and item.text(2) == "Variable":
                selected[item.text(1)] = item.text(0)
            iterator += 1
        self.tags_selected.emit(selected)
        self.accept()


# --- WORKER: OPC UA -> INFLUXDB (SUBSCRIPTION MODE) ---
class OPCSubscriptionHandler:
    """Handles incoming data change events from the OPC UA Server"""
    def __init__(self, worker):
        self.worker = worker

    def datachange_notification(self, node, val, data):
        nid = node.nodeid.to_string()
        status = data.monitored_item.Value.StatusCode
        timestamp = datetime.now(timezone.utc)
        self.worker.data_queue.put_nowait((nid, val, status, timestamp))


class OPCInfluxWorker(QThread):
    log_message = pyqtSignal(str)
    connection_status = pyqtSignal(bool)
    worker_finished = pyqtSignal()
    data_written = pyqtSignal(str)
    live_data_update = pyqtSignal(dict) 

    def __init__(self, opc_config, influx_config, selected_tags, write_mode, interval_ms, tag_metadata=None, db_measurement='kiln1'):
        super().__init__()
        self.opc_config = opc_config
        self.influx_config = influx_config
        self.db_measurement = db_measurement
        self.selected_tags = selected_tags
        self.selected_tags_nodeids = list(selected_tags.keys())
        self.tag_metadata = tag_metadata or {}
        self.interval_ms = int(max(interval_ms, 250)) 
        self._is_running = True
        
        self.value_history = {}
        self._last_errors = {}
        self.data_queue = asyncio.Queue()

    def stop(self):
        self._is_running = False
        self.log_message.emit("Stopping Subscription Gateway...")

    async def run_process(self):
        client = Client(url=self.opc_config['url'])
        await setup_opc_security(client, self.opc_config)
        
        influx = InfluxDBClient(url=self.influx_config['url'], token=self.influx_config['token'], org=self.influx_config['org'], timeout=5000)
        write_api = influx.write_api(write_options=ASYNCHRONOUS) 
        
        reconnect_delay = 5.0
        while self._is_running:
            try:
                self.log_message.emit(f"Connecting to {self.opc_config['url']}...")
                await asyncio.wait_for(client.connect(), timeout=10.0)
                self.log_message.emit(f"Connected. Requesting Aggressive Server Subscriptions...")
                self.connection_status.emit(True)
                reconnect_delay = 5.0
                
                handler = OPCSubscriptionHandler(self)
                
                params = ua.CreateSubscriptionParameters()
                params.RequestedPublishingInterval = self.interval_ms
                params.RequestedLifetimeCount = 10000
                params.RequestedMaxKeepAliveCount = 3000
                params.MaxNotificationsPerPublish = 10000
                params.PublishingEnabled = True
                params.Priority = 0
                sub = await client.create_subscription(params, handler)
                
                nodes = [client.get_node(nid) for nid in self.selected_tags_nodeids]
                CHUNK_SIZE = 50
                
                for i in range(0, len(nodes), CHUNK_SIZE):
                    chunk = nodes[i:i + CHUNK_SIZE]
                    await sub.subscribe_data_change(chunk, attr=ua.AttributeIds.Value)
                
                self.log_message.emit("✅ Successfully subscribed! Listening for active value changes...")

                while self._is_running:
                    try:
                        nid, val, status, timestamp = await asyncio.wait_for(self.data_queue.get(), timeout=1.0)
                        
                        points_to_write = []
                        ui_updates_dict = {} 
                        log_samples = []

                        def process_item(q_nid, q_val, q_status, q_ts):
                            tag_name = self.selected_tags.get(q_nid, q_nid)
                            
                            if not q_status.is_good():
                                if self._last_errors.get(q_nid) != q_status.name:
                                    self.log_message.emit(f"⚠️ Bad Quality '{tag_name}': {q_status.name}")
                                    self._last_errors[q_nid] = q_status.name
                                return False
                                
                            if q_nid in self._last_errors:
                                self.log_message.emit(f"✅ Recovered '{tag_name}'")
                                del self._last_errors[q_nid]

                            meta = self.tag_metadata.get(q_nid, {"type": "Float"})
                            expected_type = meta.get("type", "Float")
                            final_val = None
                            try:
                                if expected_type == "String": final_val = str(q_val)
                                elif expected_type == "Bool": final_val = bool(q_val)
                                else: final_val = float(q_val)
                            except: return False

                            if expected_type == "Float":
                                if q_nid not in self.value_history:
                                    self.value_history[q_nid] = deque(maxlen=5)
                                if final_val == 0.0 and len(self.value_history[q_nid]) > 0:
                                    avg = sum(self.value_history[q_nid]) / len(self.value_history[q_nid])
                                    if abs(avg) > 0.01: final_val = avg
                                else:
                                    self.value_history[q_nid].append(final_val)

                            if final_val is not None:
                                p = Point(self.db_measurement).time(q_ts, WritePrecision.NS).field(tag_name, final_val)
                                points_to_write.append(p)
                                ui_updates_dict[q_nid] = final_val 
                                if len(log_samples) < 3: log_samples.append(f"{tag_name}={final_val}")
                                return True
                            return False

                        process_item(nid, val, status, timestamp)

                        batch_count = 0
                        while not self.data_queue.empty() and batch_count < 200:
                            try:
                                q_nid, q_val, q_status, q_ts = self.data_queue.get_nowait()
                                process_item(q_nid, q_val, q_status, q_ts)
                                batch_count += 1
                            except asyncio.QueueEmpty:
                                break

                        if points_to_write:
                            write_api.write(bucket=self.influx_config['bucket'], org=self.influx_config['org'], record=points_to_write)
                            self.live_data_update.emit(ui_updates_dict)

                    except asyncio.TimeoutError:
                        continue

                try:
                    await sub.delete()
                except: pass

            except Exception as e:
                self.connection_status.emit(False)
                if not self._is_running: break
                self.log_message.emit(f"Connection lost/error: {e}. Retrying in {reconnect_delay}s...")
                try: await client.disconnect()
                except: pass
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 1.5, 60.0)

        self.log_message.emit("Gateway worker finished.")
        influx.close()
        self.worker_finished.emit()

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.run_process())
        loop.close()


# --- WORKER: WATCHER ---
class SetpointWatcherWorker(QThread):
    log_msg = pyqtSignal(str)

    def __init__(self, opc_config, influx_config, allowed_setpoints_map, db_measurement='kiln2'):
        super().__init__()
        self.opc_config = opc_config
        self.influx_config = influx_config
        self.allowed_setpoints_map = allowed_setpoints_map
        self.valid_node_ids = set(allowed_setpoints_map.values())
        self.running = True
        self.influx_bucket = influx_config.get('bucket', 'kiln_process_data')
        self.write_back_meas = db_measurement

    def stop(self):
        self.running = False

    async def run_loop(self):
        client = Client(url=self.opc_config['url'])
        await setup_opc_security(client, self.opc_config)
        influx = InfluxDBClient(
            url=self.influx_config['url'],
            token=self.influx_config['token'],
            org=self.influx_config['org'],
            timeout=5000
        )
        query_api = influx.query_api()

        try:
            await asyncio.wait_for(client.connect(), timeout=10.0)
            self.log_msg.emit(f"Watcher Active on '{self.write_back_meas}'")
            last_cmd = {}  
            last_logged_writes = {} 
            
            cached_nodes = {}
            cached_types = {}
            for nid in self.valid_node_ids:
                try:
                    nd = client.get_node(nid)
                    cached_nodes[nid] = nd
                    cached_types[nid] = await nd.read_data_type_as_variant_type()
                except Exception as e:
                    self.log_msg.emit(f"Watcher Error caching node {nid}: {e}")

            while self.running:
                q = f'from(bucket:"{self.influx_bucket}") |> range(start: -24h) |> filter(fn: (r) => r["_measurement"] == "{self.write_back_meas}") |> last()'
                try:
                    tables = await asyncio.to_thread(query_api.query, q)
                    new_cmd = {}
                    for tbl in tables:
                        for rec in tbl.records:
                            val = rec.get_value()
                            if val is not None:
                                new_cmd[rec.get_field()] = val

                    if new_cmd:
                        if any(last_cmd.get(k) != v for k, v in new_cmd.items()):
                            self.log_msg.emit(f"New Command from {self.write_back_meas}: {new_cmd}")
                        last_cmd.update(new_cmd)

                except Exception as e:
                    self.log_msg.emit(f"Watcher Query Error: {e}")
                    await asyncio.sleep(1)

                for field_name, val in last_cmd.items():
                    target_id = self.allowed_setpoints_map.get(field_name)
                    if not target_id:
                        continue
                        
                    if target_id in self.valid_node_ids and target_id in cached_nodes:
                        try:
                            node = cached_nodes[target_id]
                            vtype = cached_types.get(target_id, ua.VariantType.Double)
                            dv = ua.DataValue(ua.Variant(float(val), vtype))
                            await asyncio.wait_for(node.write_value(dv), timeout=5.0)
                            
                            if last_logged_writes.get(target_id) != val:
                                self.log_msg.emit(f"--> WROTE: {target_id} ({field_name}) = {val}")
                                last_logged_writes[target_id] = val
                        except Exception as e:
                            if last_logged_writes.get(target_id) != "ERROR":
                                self.log_msg.emit(f"Write Error {target_id}: {e}")
                                last_logged_writes[target_id] = "ERROR"

                await asyncio.sleep(0.5)
        except Exception as e:
            self.log_msg.emit(f"Watcher Error: {e}")
        finally:
            try: await client.disconnect()
            except: pass
            influx.close()

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.run_loop())
        loop.close()


# --- WORKER: SIMULATOR ---
class SimulatorWorker(QThread):
    log_message = pyqtSignal(str)
    worker_finished = pyqtSignal()
    data_written = pyqtSignal(str)
    live_data_update = pyqtSignal(dict) 

    def __init__(self, influx_config, csv_file_path, db_measurement='kiln1'):
        super().__init__()
        self.influx_config = influx_config
        self.csv_file_path = csv_file_path
        self._is_running = True
        self.db_measurement = db_measurement

    def stop(self):
        self._is_running = False
        self.log_message.emit("Stopping Simulator...")

    def run(self):
        try:
            client = InfluxDBClient(url=self.influx_config['url'], token=self.influx_config['token'],
                                    org=self.influx_config['org'], timeout=5000)
            write_api = client.write_api(write_options=ASYNCHRONOUS)

            with open(self.csv_file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.reader(f)
                headers = next(reader)
                rows = list(reader)

            idx = 0
            while self._is_running:
                row = rows[idx]
                ts = datetime.now(timezone.utc)
                display = []
                point = Point(self.db_measurement).time(ts, WritePrecision.NS)
                valid_row = False
                ui_dict = {}

                for i, col in enumerate(headers):
                    if i >= len(row): continue
                    raw = row[i].strip()
                    val = None
                    try: val = float(raw)
                    except ValueError:
                        try: val = float(raw.replace(',', '.'))
                        except ValueError: continue

                    point.field(col.strip(), val)
                    ui_dict[col.strip()] = val

                    if len(display) < 3: display.append(f"{col}={val}")
                    valid_row = True

                if valid_row:
                    try:
                        write_api.write(bucket=self.influx_config['bucket'], org=self.influx_config['org'], record=point)
                        self.live_data_update.emit(ui_dict)
                        self.data_written.emit(f"✅ Sim Write: {', '.join(display)}...")
                    except Exception as e:
                        self.log_message.emit(f"Sim Write Error: {e}")

                idx = (idx + 1) % len(rows)

                for _ in range(10):
                    if not self._is_running: break
                    time.sleep(0.1)

        except Exception as e:
            self.log_message.emit(f"Sim Error: {e}")
        finally:
            if 'client' in locals(): client.close()
            self.worker_finished.emit()


class APIWorker(QThread):
    log_message = pyqtSignal(str)

    def __init__(self, port, get_opc_client):
        super().__init__()
        self.port = port
        self.get_opc_client = get_opc_client
        self.server = None

    def run(self):
        app_api = FastAPI(title="OPC UA Write API")

        @app_api.post("/write")
        async def opc_write(request: WriteRequest):
            client = self.get_opc_client()
            if not client: raise HTTPException(503, "Not connected to OPC Server")
            try:
                node = client.get_node(request.node_id)
                await node.write_value(float(request.value) if isinstance(request.value, (int, float, str)) else request.value)
                return {"status": "ok", "node": request.node_id, "value": request.value}
            except Exception as e:
                raise HTTPException(500, str(e))

        config = uvicorn.Config(app_api, host="0.0.0.0", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            self.log_message.emit(f"FastAPI Server started on port {self.port}")
            loop.run_until_complete(self.server.serve())
        except Exception as e:
            self.log_message.emit(f"API Server Error: {e}")
        finally:
            self.log_message.emit("FastAPI Server stopped")
            loop.close()

    def stop(self):
        if self.server: self.server.should_exit = True


# --- PI WEB API HELPERS ---
def _pi_get(url, username, password, verify=False):
    resp = requests.get(url, auth=(username, password), verify=verify, timeout=10)
    resp.raise_for_status()
    return resp.json()

def _pi_search_tags(base_url, username, password, query, verify=False):
    url = f"{base_url.rstrip('/')}/search?q={requests.utils.quote(query)}&scope=pi&count=200"
    data = _pi_get(url, username, password, verify=verify)
    results = []
    for item in data.get('Items', []):
        name = item.get('Name') or item.get('name', '')
        web_id = item.get('WebId') or item.get('webId', '')
        if name and web_id:
            results.append({'name': name, 'webId': web_id})
    return results


# --- PI TAG SEARCH DIALOG ---
class PITagSearchDialog(QDialog):
    tags_added = pyqtSignal(list)

    def __init__(self, pi_url, pi_user, pi_password, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Search PI Tags")
        self.resize(700, 450)
        self.pi_url = pi_url
        self.pi_user = pi_user
        self.pi_password = pi_password

        layout = QVBoxLayout(self)
        h = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter tag name pattern (e.g. KILN*)")
        self.search_btn = QPushButton("🔍 Search")
        self.search_btn.clicked.connect(self._do_search)
        self.search_input.returnPressed.connect(self._do_search)
        h.addWidget(self.search_input)
        h.addWidget(self.search_btn)
        layout.addLayout(h)

        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["PI Tag Name", "WebID"])
        self.results_tree.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.results_tree.setColumnWidth(0, 320)
        layout.addWidget(self.results_tree)

        self.status_label = QLabel("Enter a search term above.")
        layout.addWidget(self.status_label)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _do_search(self):
        q = self.search_input.text().strip()
        if not q: return
        self.status_label.setText("Searching...")
        self.search_btn.setEnabled(False)
        self.results_tree.clear()

        def run():
            try:
                tags = _pi_search_tags(self.pi_url, self.pi_user, self.pi_password, q)
                self._populate_result(tags)
            except Exception as e:
                self.status_label.setText(f"Error: {e}")
                self.search_btn.setEnabled(True)

        threading.Thread(target=run, daemon=True).start()

    def _populate_result(self, tags):
        self.results_tree.clear()
        for t in tags:
            item = QTreeWidgetItem([t['name'], t['webId']])
            self.results_tree.addTopLevelItem(item)
        self.status_label.setText(f"Found {len(tags)} tag(s). Select and click OK to add.")
        self.search_btn.setEnabled(True)

    def _on_accept(self):
        selected = []
        for item in self.results_tree.selectedItems():
            selected.append({'name': item.text(0), 'webId': item.text(1), 'alias': item.text(0)})
        if selected: self.tags_added.emit(selected)
        self.accept()


# --- WORKER: PI WEB API -> INFLUXDB ---
class PIInfluxWorker(QThread):
    log_message = pyqtSignal(str)
    data_written = pyqtSignal(str)
    live_data_update = pyqtSignal(dict) 
    worker_finished = pyqtSignal()

    def __init__(self, pi_url, pi_user, pi_password, influx_config, pi_tags, interval_sec, use_api_key=False, pi_api_key="", db_measurement='kiln1'):
        super().__init__()
        self.pi_url = pi_url.rstrip('/')
        self.pi_user = pi_user
        self.pi_password = pi_password
        self.influx_config = influx_config
        self.pi_tags = pi_tags
        self.interval_sec = interval_sec
        self.use_api_key = use_api_key
        self.pi_api_key = pi_api_key
        self._is_running = True
        self.db_measurement = db_measurement

    def stop(self):
        self._is_running = False
        self.log_message.emit("Stopping PI Gateway...")

    def run(self):
        try:
            influx = InfluxDBClient(
                url=self.influx_config['url'],
                token=self.influx_config['token'],
                org=self.influx_config['org'],
                timeout=5000
            )
            write_api = influx.write_api(write_options=ASYNCHRONOUS)
            self.log_message.emit(f"PI Gateway started → {self.db_measurement}")

            web_ids = [t['webId'] for t in self.pi_tags]
            alias_map = {t['webId']: t.get('alias') or t['name'] for t in self.pi_tags}
            use_stream_url_mode = any(t.get('stream_url') or t['webId'].startswith('http') for t in self.pi_tags)

            while self._is_running:
                try:
                    ts = datetime.now(timezone.utc)
                    point = Point(self.db_measurement).time(ts, WritePrecision.NS)
                    log_samples = []
                    ui_dict = {}

                    if use_stream_url_mode:
                        for t in self.pi_tags:
                            stream_url = t.get('stream_url') or t['webId']
                            alias = alias_map.get(t['webId'], t.get('alias', t['name']))
                            try:
                                auth = None if self.use_api_key else (self.pi_user, self.pi_password)
                                resp = requests.get(stream_url, auth=auth, verify=False, timeout=5)
                                resp.raise_for_status()
                                data = resp.json()
                                
                                if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                                    raw = data["data"][0].get("Value", data)
                                else:
                                    val_obj = data.get('Value', data)
                                    raw = val_obj.get('Value', val_obj) if isinstance(val_obj, dict) else val_obj
                                if raw is None: continue
                                try:
                                    val = float(raw)
                                    point.field(alias, val)
                                    ui_dict[t['webId']] = val
                                    if len(log_samples) < 3: log_samples.append(f"{alias}={val}")
                                except (ValueError, TypeError): continue
                            except Exception as e:
                                self.log_message.emit(f"PI Stream Error [{alias}]: {e}")
                    else:
                        batch_url = f"{self.pi_url}/streamsets/value"
                        payload = [{'WebId': wid} for wid in web_ids]
                        auth = None if self.use_api_key else (self.pi_user, self.pi_password)
                        resp = requests.post(batch_url, json=payload, auth=auth, verify=False, timeout=10)
                        resp.raise_for_status()
                        items = resp.json().get('Items', [])
                        for item in items:
                            wid = item.get('WebId', '')
                            val_obj = item.get('Value', {})
                            raw = val_obj.get('Value', val_obj) if isinstance(val_obj, dict) else val_obj
                            alias = alias_map.get(wid, wid)
                            if raw is None: continue
                            try:
                                val = float(raw)
                                point.field(alias, val)
                                ui_dict[wid] = val
                                if len(log_samples) < 3: log_samples.append(f"{alias}={val}")
                            except (ValueError, TypeError): continue

                    write_api.write(bucket=self.influx_config['bucket'], org=self.influx_config['org'], record=point)
                    self.live_data_update.emit(ui_dict)
                    # self.data_written.emit(f"✅ PI: {', '.join(log_samples)}...")

                except Exception as e:
                    self.log_message.emit(f"PI Read Error: {e}")

                for _ in range(int(self.interval_sec * 10)):
                    if not self._is_running: break
                    time.sleep(0.1)

        except Exception as e:
            self.log_message.emit(f"PI Gateway Error: {e}")
        finally:
            influx.close()
            self.worker_finished.emit()

# --- MAIN WINDOW ---
class MainWindow(QMainWindow):
    log_signal = pyqtSignal(str)
    opc_client_connected = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("OPC UA to InfluxDB Gateway")
        if os.path.exists(ICON_FILE): self.setWindowIcon(QIcon(ICON_FILE))
        self.resize(1400, 900)

        self.opc_worker = None
        self.simulator_worker = None
        self.watcher_worker = None
        self.api_worker = None
        self.pi_worker = None
        self.opc_client = None
        self.selections = self._load_selections()
        self.selected_opc_tags = self.selections.get("selected_opc_tags", {})
        self.output_tags = set(self.selections.get("output_tags", []))
        self.tag_metadata = self.selections.get("tag_metadata", {})
        
        for nid in self.selected_opc_tags:
            if nid not in self.tag_metadata:
                self.tag_metadata[nid] = {"type": "Float"}
        self.model_setpoints = {}
        self.csv_file_path = self.selections.get("csv_file_path")
        self.tag_item_map = {}
        self.pi_tags = self.selections.get("pi_tags", [])
        self.pi_tag_item_map = {}  

        self.cert_folder = pathlib.Path("./certificates")
        self.cert_folder.mkdir(exist_ok=True)
        self.client_cert_path = self.cert_folder / "client_cert.der"
        self.client_key_path = self.cert_folder / "client_key.pem"

        self._setup_menu()
        self._setup_ui()
        self._setup_logging()
        self._apply_stylesheet()
        self._update_cert_status_ui()
        self._update_ui_state_initial()
        self.opc_client_connected.connect(self._update_opc_connection_label)

    def _setup_logging(self):
        self.log_signal.connect(self.log_widget.appendPlainText)
        handler = QtLogHandler(self.log_signal)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    def _load_selections(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f: return json.load(f)
            except: pass
        return {}

    def _save_selections(self):
        self.selections["opc_endpoint"] = self.opc_endpoint_input.text()
        self.selections["opc_username"] = self.opc_username_input.text()
        self.selections["opc_password"] = self.opc_password_input.text()
        self.selections["api_port"] = getattr(self, 'api_port_input', type('obj', (object,), {'value': lambda: 8000})).value()
        self.selections["influx_url"] = self.influx_url_input.text()
        self.selections["influx_token"] = self.influx_token_input.text()
        self.selections["influx_org"] = self.influx_org_input.text()
        self.selections["influx_bucket"] = self.influx_bucket_input.text()
        self.selections["selected_opc_tags"] = self.selected_opc_tags
        self.selections["output_tags"] = list(self.output_tags)
        self.selections["tag_metadata"] = self.tag_metadata
        self.selections["opc_measurement"] = self.opc_measurement_input.text()
        self.selections["pi_measurement"] = self.pi_measurement_input.text()
        self.selections["csv_file_path"] = self.csv_file_path
        self.selections["pi_url"] = self.pi_url_input.text()
        self.selections["pi_username"] = self.pi_username_input.text()
        self.selections["pi_password"] = self.pi_password_input.text()
        self.selections["use_pi_api_key"] = self.pi_use_api_key_chk.isChecked()
        self.selections["pi_api_key"] = self.pi_api_key_input.text()
        self.selections["pi_tags"] = self.pi_tags
        self.selections["opc_browse_path"] = self.opc_browse_path_input.text()
        self.selections["write_interval"] = self.write_interval_spinbox.value()
        try:
            with open(CONFIG_FILE, 'w') as f: json.dump(self.selections, f, indent=4)
        except: pass

    def _setup_menu(self):
        menu = self.menuBar().addMenu("&File")
        menu.addAction("⚙ Settings (config.py)", lambda: ConfigEditorDialog(self).exec())
        menu.addAction("📂 Load Model JSON", self._load_model_json_dialog)
        menu.addSeparator()
        menu.addAction("Exit", self.close)

    def _load_model_json_dialog(self):
        f, _ = QFileDialog.getOpenFileName(self, "Open Model JSON", "", "JSON (*.json)")
        if f: self._parse_model_json(f)

    def _parse_model_json(self, path):
        try:
            with open(path, 'r') as f: data = json.load(f)
            self.model_setpoints = {}
            for k, v in data.get("control_variables", {}).items():
                if v.get("is_setpoint"):
                    target_name = v.get("tag_name")
                    self.output_tags.add(target_name)
                    matched_nid = None
                    for nid, opc_name in self.selected_opc_tags.items():
                        if opc_name == target_name:
                            matched_nid = nid
                            break
                    
                    if matched_nid:
                        self.model_setpoints[k] = matched_nid
                    else:
                        self.log_widget.appendPlainText(f"⚠️ Warning: Model requires '{target_name}' but it is not mapped to a Node ID.")

            self.status_bar.showMessage(f"Loaded {len(self.model_setpoints)} setpoints", 4000)
            self.watcher_chk.setEnabled(True)
            self.watcher_chk.setText(f"Enable Automated Write-Back ({len(self.model_setpoints)} mapped tags)")
            self._update_selected_tags_list_widget()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _setup_ui(self):
        self.setCentralWidget(QScrollArea())
        central = QWidget()
        self.centralWidget().setWidget(central)
        self.centralWidget().setWidgetResizable(True)
        layout = QHBoxLayout(central)

        left = QVBoxLayout()

        g1 = QGroupBox("1. OPC UA Server Configuration")
        f1 = QFormLayout()
        self.opc_endpoint_input = QLineEdit(self.selections.get("opc_endpoint", "opc.tcp://localhost:4840"))
        self.opc_username_input = QLineEdit(self.selections.get("opc_username", ""))
        self.opc_password_input = QLineEdit(self.selections.get("opc_password", ""))
        self.opc_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.opc_browse_path_input = QLineEdit(self.selections.get("opc_browse_path", "0:Objects"))
        f1.addRow("Endpoint:", self.opc_endpoint_input)
        f1.addRow("Username:", self.opc_username_input)
        f1.addRow("Password:", self.opc_password_input)
        f1.addRow("Browse Path:", self.opc_browse_path_input)
        
        h_cert = QHBoxLayout()
        self.generate_cert_button = QPushButton("🔐 Generate Certs")
        self.generate_cert_button.clicked.connect(self._generate_certificates)
        self.cert_status_label = QLabel("Validating certs...")
        self.use_cert_security_chk = QCheckBox("Enable Cert Security")
        self.use_cert_security_chk.setToolTip(
            "Check to use the generated cert files for OPC UA SignAndEncrypt.\n"
            "Leave unchecked for Anonymous or username/password only."
        )
        h_cert.addWidget(self.generate_cert_button)
        h_cert.addWidget(self.cert_status_label)
        h_cert.addWidget(self.use_cert_security_chk)
        f1.addRow(h_cert)

        h1 = QHBoxLayout()
        self.connect_opc_button = QPushButton("🌐 Connect & Browse")
        self.connect_opc_button.clicked.connect(self.connect_and_browse_opc_server)
        self.disconnect_opc_button = QPushButton("🔌 Disconnect")
        self.disconnect_opc_button.clicked.connect(self.disconnect_opc_server)
        self.disconnect_opc_button.setEnabled(False)
        default_opc = getattr(config, "DB_MEASUREMENT_OPC", self.selections.get("opc_measurement", "kiln1_opc"))
        self.opc_measurement_input = QLineEdit(default_opc)
        f1.addRow("Measurement:", self.opc_measurement_input)
        h1.addWidget(self.connect_opc_button)
        h1.addWidget(self.disconnect_opc_button)
        f1.addRow(h1)
        self.opc_connection_status_label = QLabel("Status: Disconnected")
        f1.addRow(self.opc_connection_status_label)
        g1.setLayout(f1)
        left.addWidget(g1)

        g2 = QGroupBox("2. InfluxDB Configuration")
        f2 = QFormLayout()
        self.influx_url_input = QLineEdit(self.selections.get("influx_url", "http://localhost:8086"))
        self.influx_token_input = QLineEdit(self.selections.get("influx_token", ""))
        self.influx_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.influx_org_input = QLineEdit(self.selections.get("influx_org", "my-org"))
        self.influx_bucket_input = QLineEdit(self.selections.get("influx_bucket", "my-bucket"))
        f2.addRow("URL:", self.influx_url_input)
        f2.addRow("Token:", self.influx_token_input)
        f2.addRow("Org:", self.influx_org_input)
        f2.addRow("Bucket:", self.influx_bucket_input)

        h2 = QHBoxLayout()
        self.write_per_sec_radio = QRadioButton("Interval")
        self.write_on_change_radio = QRadioButton("On Change")
        self.write_interval_spinbox = QSpinBox()
        self.write_interval_spinbox.setRange(100, 60000)
        self.write_interval_spinbox.setValue(self.selections.get("write_interval", 1000))
        self.write_per_sec_radio.setChecked(True)
        h2.addWidget(self.write_per_sec_radio)
        h2.addWidget(self.write_interval_spinbox)
        h2.addWidget(self.write_on_change_radio)
        f2.addRow("Mode:", h2)

        self.influx_test_button = QPushButton("Test Connection")
        self.influx_test_button.clicked.connect(self.test_influxdb_connection)
        f2.addRow(self.influx_test_button)
        self.influx_connection_status_label = QLabel("Status: Not Tested")
        f2.addRow(self.influx_connection_status_label)
        g2.setLayout(f2)
        left.addWidget(g2)

        g3 = QGroupBox("3. Manual Write (Single Output)")
        f3 = QFormLayout()
        self.write_tag_combo = QComboBox()
        self.write_value_input = QLineEdit()
        self.write_button = QPushButton("Write Value")
        self.write_button.clicked.connect(self._on_write_button_clicked)
        f3.addRow("Tag:", self.write_tag_combo)
        f3.addRow("Value:", self.write_value_input)
        f3.addRow(self.write_button)
        g3.setLayout(f3)
        left.addWidget(g3)

        g4 = QGroupBox("4. Automated Model Write-Back")
        v4 = QVBoxLayout()
        self.watcher_chk = QCheckBox("Enable Automated Write-Back")
        self.watcher_chk.setEnabled(True)
        self.watcher_chk.toggled.connect(self.toggle_write_watcher)
        v4.addWidget(self.watcher_chk)
        self.watcher_status = QLabel("Status: Stopped")
        v4.addWidget(self.watcher_status)
        g4.setLayout(v4)
        left.addWidget(g4)

        g5 = QGroupBox("5. Live Gateway Control")
        h5 = QHBoxLayout()
        self.start_gateway_button = QPushButton("▶ Start Live")
        self.start_gateway_button.clicked.connect(self.start_gateway)
        self.stop_gateway_button = QPushButton("■ Stop Live")
        self.stop_gateway_button.clicked.connect(self.stop_gateway)
        self.stop_gateway_button.setEnabled(False)
        h5.addWidget(self.start_gateway_button)
        h5.addWidget(self.stop_gateway_button)
        g5.setLayout(h5)
        left.addWidget(g5)

        g6 = QGroupBox("6. Demo Simulator")
        v6 = QVBoxLayout()
        h6a = QHBoxLayout()
        self.csv_path_line_edit = QLineEdit(self.csv_file_path or "")
        self.csv_path_line_edit.setReadOnly(True)
        self.load_csv_button = QPushButton("Load CSV...")
        self.load_csv_button.clicked.connect(self._load_csv_file)
        h6a.addWidget(self.csv_path_line_edit)
        h6a.addWidget(self.load_csv_button)
        v6.addLayout(h6a)

        h6b = QHBoxLayout()
        self.start_simulator_button = QPushButton("▶ Start Sim")
        self.start_simulator_button.clicked.connect(self.start_simulator)
        self.start_simulator_button.setEnabled(bool(self.csv_file_path))
        self.stop_simulator_button = QPushButton("■ Stop Sim")
        self.stop_simulator_button.clicked.connect(self.stop_simulator)
        self.stop_simulator_button.setEnabled(False)
        h6b.addWidget(self.start_simulator_button)
        h6b.addWidget(self.stop_simulator_button)
        v6.addLayout(h6b)
        g6.setLayout(v6)
        left.addWidget(g6)

        g7 = QGroupBox("7. FastAPI Write Server")
        h7 = QHBoxLayout()
        self.api_port_input = QSpinBox()
        self.api_port_input.setRange(1000, 65535)
        self.api_port_input.setValue(self.selections.get("api_port", 8000))
        self.start_api_button = QPushButton("▶ Start API")
        self.start_api_button.clicked.connect(self.start_api)
        self.stop_api_button = QPushButton("■ Stop API")
        self.stop_api_button.clicked.connect(self.stop_api)
        self.stop_api_button.setEnabled(False)
        h7.addWidget(QLabel("Port:"))
        h7.addWidget(self.api_port_input)
        h7.addWidget(self.start_api_button)
        h7.addWidget(self.stop_api_button)
        g7.setLayout(h7)
        left.addWidget(g7)

        g8 = QGroupBox("8. OSI PI Server (PI Web API)")
        f8 = QFormLayout()
        self.pi_url_input = QLineEdit(self.selections.get("pi_url", "https://mypiserver/piwebapi"))
        self.pi_username_input = QLineEdit(self.selections.get("pi_username", ""))
        self.pi_password_input = QLineEdit(self.selections.get("pi_password", ""))
        self.pi_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pi_api_key_input = QLineEdit(self.selections.get("pi_api_key", ""))
        self.pi_use_api_key_chk = QCheckBox("Use API Key")
        self.pi_use_api_key_chk.setChecked(self.selections.get("use_pi_api_key", False))
        self.pi_use_api_key_chk.toggled.connect(self._toggle_pi_auth_mode)

        f8.addRow("PI Web API URL:", self.pi_url_input)
        default_pi = getattr(config, "DB_MEASUREMENT_PI", self.selections.get("pi_measurement", "kiln1_pi"))
        self.pi_measurement_input = QLineEdit(default_pi)
        f8.addRow("Measurement:", self.pi_measurement_input)
        f8.addRow(self.pi_use_api_key_chk)
        f8.addRow("API Key:", self.pi_api_key_input)
        f8.addRow("Username:", self.pi_username_input)
        f8.addRow("Password:", self.pi_password_input)
        self._toggle_pi_auth_mode()

        h8a = QHBoxLayout()
        self.pi_search_button = QPushButton("🔍 Search PI Tags...")
        self.pi_search_button.clicked.connect(self._open_pi_search)
        self.pi_manual_add_button = QPushButton("➕ Manual Add")
        self.pi_manual_add_button.clicked.connect(self._manual_add_pi_tag)
        self.pi_paste_urls_button = QPushButton("📋 Paste Stream URLs")
        self.pi_paste_urls_button.clicked.connect(self._paste_pi_stream_urls)
        self.pi_import_csv_button = QPushButton("📂 Import CSV")
        self.pi_import_csv_button.clicked.connect(self._import_pi_tags_from_csv)
        self.pi_export_template_button = QPushButton("📄 Export Template")
        self.pi_export_template_button.clicked.connect(self._export_pi_tags_template)
        self.pi_clear_button = QPushButton("✕ Clear All")
        self.pi_clear_button.clicked.connect(self._clear_pi_tags)
        h8a.addWidget(self.pi_search_button)
        h8a.addWidget(self.pi_manual_add_button)
        h8a.addWidget(self.pi_paste_urls_button)
        h8a.addWidget(self.pi_import_csv_button)
        h8a.addWidget(self.pi_export_template_button)
        h8a.addWidget(self.pi_clear_button)
        f8.addRow(h8a)

        h8b = QHBoxLayout()
        self.pi_interval_spin = QSpinBox()
        self.pi_interval_spin.setRange(1, 3600)
        self.pi_interval_spin.setValue(self.selections.get("pi_interval", 5))
        self.pi_interval_spin.setSuffix(" s")
        self.start_pi_button = QPushButton("▶ Start PI")
        self.start_pi_button.clicked.connect(self.start_pi_gateway)
        self.stop_pi_button = QPushButton("■ Stop PI")
        self.stop_pi_button.clicked.connect(self.stop_pi_gateway)
        self.stop_pi_button.setEnabled(False)
        h8b.addWidget(QLabel("Interval:"))
        h8b.addWidget(self.pi_interval_spin)
        h8b.addWidget(self.start_pi_button)
        h8b.addWidget(self.stop_pi_button)
        f8.addRow(h8b)
        g8.setLayout(f8)
        left.addWidget(g8)

        left.addStretch()
        layout.addLayout(left, 1)

        right = QSplitter(Qt.Orientation.Vertical)

        g_tags = QGroupBox("OPC UA Tags to Monitor")
        l_tags = QVBoxLayout()
        self.selected_tags_tree = QTreeWidget()
        self.selected_tags_tree.setHeaderLabels(["Tag Name (editable)", "NodeID", "Mode", "Data Type", "Value"])
        self.selected_tags_tree.setColumnWidth(0, 220)
        self.selected_tags_tree.setColumnWidth(2, 80)
        self.selected_tags_tree.setColumnWidth(3, 100)
        self.selected_tags_tree.setToolTip("Double-click Tag Name to rename. Click 'Mode' or 'Data Type' to toggle them.")
        self.selected_tags_tree.itemClicked.connect(self._on_tag_item_clicked)
        self.selected_tags_tree.itemChanged.connect(self._on_tag_name_changed)
        l_tags.addWidget(self.selected_tags_tree)

        h_tags = QHBoxLayout()
        self.import_tags_button = QPushButton("Import CSV")
        self.import_tags_button.clicked.connect(self._import_tags_from_csv)
        self.export_tags_button = QPushButton("Export CSV")
        self.export_tags_button.clicked.connect(self._export_tags_to_csv)
        self.toggle_tag_type_button = QPushButton("Toggle I/O")
        self.toggle_tag_type_button.clicked.connect(self._toggle_tag_type)
        self.remove_selected_tags_button = QPushButton("Remove")
        self.remove_selected_tags_button.clicked.connect(self._remove_selected_tags)
        self.clear_all_tags_button = QPushButton("Clear All")
        self.clear_all_tags_button.clicked.connect(self._clear_all_tags)

        h_tags.addWidget(self.import_tags_button)
        h_tags.addWidget(self.export_tags_button)
        h_tags.addWidget(self.toggle_tag_type_button)
        h_tags.addWidget(self.remove_selected_tags_button)
        h_tags.addWidget(self.clear_all_tags_button)
        l_tags.addLayout(h_tags)
        g_tags.setLayout(l_tags)
        right.addWidget(g_tags)

        g_pi_tags = QGroupBox("OSI PI Tags (PI \u2192 InfluxDB)")
        l_pi = QVBoxLayout()
        self.pi_tags_tree = QTreeWidget()
        self.pi_tags_tree.setHeaderLabels(["PI Tag Name", "Alias (InfluxDB Field)", "WebID", "Last Value"])
        self.pi_tags_tree.setColumnWidth(0, 180)
        self.pi_tags_tree.setColumnWidth(1, 160)
        self.pi_tags_tree.setColumnWidth(2, 200)
        self.pi_tags_tree.itemDoubleClicked.connect(self._edit_pi_tag_alias)
        l_pi.addWidget(self.pi_tags_tree)
        h_pi_btns = QHBoxLayout()
        self.pi_remove_btn = QPushButton("Remove")
        self.pi_remove_btn.clicked.connect(self._remove_pi_tag)
        h_pi_btns.addStretch()
        h_pi_btns.addWidget(self.pi_remove_btn)
        l_pi.addLayout(h_pi_btns)
        g_pi_tags.setLayout(l_pi)
        right.addWidget(g_pi_tags)

        self._refresh_pi_tags_tree()

        g_log = QGroupBox("Execution Log")
        l_log = QVBoxLayout()
        self.log_widget = QPlainTextEdit()
        self.log_widget.setReadOnly(True)
        l_log.addWidget(self.log_widget)
        h_log = QHBoxLayout()
        self.export_log_button = QPushButton("Export Log")
        self.export_log_button.clicked.connect(self.export_log)
        self.clear_log_button = QPushButton("Clear")
        self.clear_log_button.clicked.connect(self.log_widget.clear)
        h_log.addWidget(self.export_log_button)
        h_log.addWidget(self.clear_log_button)
        l_log.addLayout(h_log)
        g_log.setLayout(l_log)
        right.addWidget(g_log)

        layout.addWidget(right, 1)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready.")

    def _apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow, QDialog, QWidget { 
                background-color: #1e1e1e; 
                color: #f0f0f0; 
                font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                font-size: 10pt;
            }
            QGroupBox { 
                background-color: #252526; 
                color: #e0e0e0; 
                border: 1px solid #3e3e3e; 
                border-radius: 6px; 
                margin-top: 20px; 
                padding: 15px 5px 5px 5px; 
                font-weight: bold; 
            }
            QGroupBox::title { 
                subcontrol-origin: margin; 
                subcontrol-position: top left; 
                padding: 0 5px; 
                left: 10px;
                color: #61dafb; 
                background-color: #252526;
            }
            QLineEdit, QPlainTextEdit, QTreeWidget, QListWidget, QComboBox, QSpinBox { 
                background-color: #333333; 
                color: #f0f0f0; 
                border: 1px solid #555555; 
                border-radius: 4px;
                padding: 5px; 
            }
            QHeaderView::section {
                background-color: #2d2d30;
                color: #f0f0f0;
                padding: 5px;
                border: 1px solid #3e3e3e;
            }
            QTreeWidget::item:selected {
                background-color: #094771;
                color: white;
            }
            QPushButton { 
                background-color: #3a3a3a; 
                color: white; 
                border: 1px solid #555555; 
                padding: 6px 12px; 
                border-radius: 4px; 
                font-weight: bold; 
            }
            QPushButton:hover { 
                background-color: #4a4a4a; 
                border-color: #61dafb;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
            QPushButton:disabled { 
                background-color: #252526; 
                color: #666666; 
                border-color: #3e3e3e;
            }
            QLabel { 
                color: #cccccc; 
            }
            QStatusBar {
                background-color: #007acc;
                color: white;
            }
            QSplitter::handle {
                background-color: #3e3e3e;
            }
        """)

    def _update_ui_state_initial(self):
        self._update_selected_tags_list_widget()
        self._update_write_combo()

    def _update_cert_status_ui(self):
        if self.client_cert_path.exists() and self.client_key_path.exists():
            self.cert_status_label.setText("Certs: Ready")
            self.cert_status_label.setStyleSheet("color: #4caf50;")
        else:
            self.cert_status_label.setText("Certs: None")
            self.cert_status_label.setStyleSheet("color: #ff9800;")
            
    def _generate_certificates(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.x509.general_name import DNSName, IPAddress, UniformResourceIdentifier
            import datetime
            import ipaddress
            
            self.cert_folder.mkdir(exist_ok=True)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"HE"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"HE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IN"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"CIMPOR OPC CLIENT UA"),
            ])

            valid_from = datetime.datetime.now(datetime.timezone.utc)
            valid_to = valid_from + datetime.timedelta(days=365)

            alt_names = x509.SubjectAlternativeName([
                UniformResourceIdentifier("urn:freeopcua:client"),
                DNSName("PTLXAIPYROCPS01"),
                IPAddress(ipaddress.IPv4Address("10.1.250.1")),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(valid_from)
                .not_valid_after(valid_to)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(alt_names, critical=False)
                .add_extension(
                    x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]),
                    critical=False,
                )
                .sign(private_key, hashes.SHA256())
            )
            
            with open(self.client_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.DER))
                
            with open(self.client_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            self._update_cert_status_ui()
            QMessageBox.information(self, "Success", "Certificates generated successfully in ./certificates/")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate certificates: {e}")

    def _get_opc_config(self):
        return {
            'url': self.opc_endpoint_input.text(),
            'username': self.opc_username_input.text(),
            'password': self.opc_password_input.text(),
            'cert_path': str(self.client_cert_path),
            'key_path': str(self.client_key_path),
            'use_cert_security': self.use_cert_security_chk.isChecked()
        }

    @qasync.asyncSlot()
    async def connect_and_browse_opc_server(self):
        self.connect_opc_button.setEnabled(False)
        self.connect_opc_button.setText("Connecting...")
        try:
            if self.opc_client: await self.opc_client.disconnect()
            self.opc_client = Client(url=self.opc_endpoint_input.text())
            await setup_opc_security(self.opc_client, self._get_opc_config())
            await asyncio.wait_for(self.opc_client.connect(), timeout=10.0)
            self.opc_client_connected.emit(True)
            self._save_selections()
            dlg = ServerBrowseDialog(self)
            dlg.tags_selected.connect(self._on_tags_selected)
            await dlg.populate_tree(self.opc_client, self.selected_opc_tags.keys(), self.opc_browse_path_input.text())
            
            done = asyncio.get_event_loop().create_future()
            dlg.finished.connect(lambda r: done.set_result(r) if not done.done() else None)
            dlg.show()
            await done

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.opc_client_connected.emit(False)
        finally:
            self.connect_opc_button.setText("🌐 Connect & Browse")
            self.connect_opc_button.setEnabled(not bool(self.opc_client))

    @qasync.asyncSlot()
    async def disconnect_opc_server(self):
        client_to_close = self.opc_client
        self.opc_client = None

        self.connect_opc_button.setText("🌐 Connect & Browse")
        self.connect_opc_button.setEnabled(True)
        self.disconnect_opc_button.setText("🔌 Disconnect")
        self.disconnect_opc_button.setEnabled(False)
        self.opc_connection_status_label.setText("Status: Disconnected")
        self.opc_connection_status_label.setStyleSheet("color: #f44336; font-weight: bold;")
        self._update_write_combo()
        if self.stop_gateway_button.isEnabled(): self.stop_gateway()
        self.opc_client_connected.emit(False)
        self.status_bar.showMessage("Disconnected.", 2000)

        if client_to_close:
            try:
                await asyncio.wait_for(client_to_close.disconnect(), timeout=1.0)
            except Exception:
                pass

    @pyqtSlot(bool)
    def _update_opc_connection_label(self, connected):
        self.opc_connection_status_label.setText("Status: Connected" if connected else "Status: Disconnected")
        self.opc_connection_status_label.setStyleSheet(
            f"color: {'#4caf50' if connected else '#f44336'}; font-weight: bold;")
        self.connect_opc_button.setEnabled(not connected)
        self.disconnect_opc_button.setEnabled(connected)
        self.write_button.setEnabled(connected)
        
        is_running = (self.opc_worker and self.opc_worker.isRunning()) or (self.simulator_worker and self.simulator_worker.isRunning())
        self.start_gateway_button.setEnabled(connected and not is_running)
        self._update_write_combo()

    def start_gateway(self):
        if not self.selected_opc_tags: return QMessageBox.warning(self, "No Tags", "Select tags first")
        self.start_gateway_button.setEnabled(False)
        self.stop_gateway_button.setEnabled(True)
        self.start_simulator_button.setEnabled(False)

        conf = {'url': self.influx_url_input.text(), 'token': self.influx_token_input.text(),
                'org': self.influx_org_input.text(), 'bucket': self.influx_bucket_input.text()}
        self.opc_worker = OPCInfluxWorker(self._get_opc_config(), conf, self.selected_opc_tags,
                                          'per_second', self.write_interval_spinbox.value(),
                                          tag_metadata=self.tag_metadata,
                                          db_measurement=self.opc_measurement_input.text())
        self.opc_worker.log_message.connect(self.log_widget.appendPlainText)
        self.opc_worker.data_written.connect(lambda x: self.status_bar.showMessage(x, 2000))
        self.opc_worker.live_data_update.connect(self._on_live_data_update)
        self.opc_worker.worker_finished.connect(self.stop_gateway)
        self.opc_worker.start()

    def stop_gateway(self):
        self.stop_gateway_button.setEnabled(False)
        if self.opc_worker: 
            try: self.opc_worker.log_message.disconnect() 
            except: pass
            self.opc_worker.stop()
            self.opc_worker = None
        self.start_gateway_button.setEnabled(self.opc_client is not None)
        self.start_simulator_button.setEnabled(bool(self.csv_file_path))

    def _toggle_pi_auth_mode(self):
        use_api = self.pi_use_api_key_chk.isChecked()
        self.pi_api_key_input.setEnabled(use_api)
        self.pi_username_input.setEnabled(not use_api)
        self.pi_password_input.setEnabled(not use_api)

    def _open_pi_search(self):
        dlg = PITagSearchDialog(
            self.pi_url_input.text(),
            self.pi_username_input.text(),
            self.pi_password_input.text(),
            parent=self
        )
        dlg.tags_added.connect(self._on_pi_tags_added)
        dlg.exec()

    @pyqtSlot(list)
    def _on_pi_tags_added(self, tags):
        existing_ids = {t['webId'] for t in self.pi_tags}
        for t in tags:
            if t['webId'] not in existing_ids:
                self.pi_tags.append(t)
        self._refresh_pi_tags_tree()
        self._save_selections()

    def _refresh_pi_tags_tree(self):
        self.pi_tags_tree.clear()
        self.pi_tag_item_map.clear()
        for t in self.pi_tags:
            item = QTreeWidgetItem([t['name'], t.get('alias', t['name']), t['webId'], '---'])
            self.pi_tags_tree.addTopLevelItem(item)
            self.pi_tag_item_map[t['webId']] = item

    def _edit_pi_tag_alias(self, item, column):
        if column != 1: return
        web_id = item.text(2)
        from PyQt6.QtWidgets import QInputDialog
        new_alias, ok = QInputDialog.getText(self, "Edit Alias", f"Alias for {item.text(0)}:", text=item.text(1))
        if ok and new_alias.strip():
            item.setText(1, new_alias.strip())
            for t in self.pi_tags:
                if t['webId'] == web_id:
                    t['alias'] = new_alias.strip()
            self._save_selections()

    def _remove_pi_tag(self):
        for item in self.pi_tags_tree.selectedItems():
            web_id = item.text(2)
            self.pi_tags = [t for t in self.pi_tags if t['webId'] != web_id]
        self._refresh_pi_tags_tree()
        self._save_selections()

    def _clear_pi_tags(self):
        self.pi_tags = []
        self._refresh_pi_tags_tree()
        self._save_selections()

    def _manual_add_pi_tag(self):
        from PyQt6.QtWidgets import QInputDialog
        web_id, ok = QInputDialog.getText(self, "Manual Add PI Tag", "Enter the WebID for the PI Tag:")
        if ok and web_id.strip():
            web_id = web_id.strip()
            existing_ids = {t['webId'] for t in self.pi_tags}
            if web_id in existing_ids:
                QMessageBox.information(self, "Info", "WebID already exists in the list.")
                return
            
            alias, ok2 = QInputDialog.getText(self, "Manual Add PI Tag", "Enter an intuitive Alias/Name for this WebID:")
            if ok2 and alias.strip():
                name = alias.strip()
            else:
                name = "Manual_Tag"

            self.pi_tags.append({'name': name, 'webId': web_id, 'alias': name})
            self._refresh_pi_tags_tree()
            self._save_selections()
            self.status_bar.showMessage(f"Manually added WebID: {web_id}", 3000)

    def _paste_pi_stream_urls(self):
        from PyQt6.QtWidgets import QDialog, QTextEdit, QDialogButtonBox, QVBoxLayout, QLabel
        import re
        dlg = QDialog(self)
        dlg.setWindowTitle("Paste PI Web API Stream URLs")
        dlg.setMinimumSize(700, 400)
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel(
            "Paste your PI Web API stream URLs below, one per line.\n"
            "Format: https://server/piwebapi/streams/{WebID}/value\n"
            "The WebID will be extracted automatically."
        ))
        text_edit = QTextEdit()
        layout.addWidget(text_edit)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted: return

        raw_text = text_edit.toPlainText()
        stream_pattern = re.compile(r'https?://[^/]+/piwebapi/streams/([^/]+)/value', re.IGNORECASE)
        path_pattern = re.compile(r'https?://[^/]+/[^/]+/[^/]+/data\?path=(.+)', re.IGNORECASE)
        
        existing_ids = {t['webId'] for t in self.pi_tags}
        added_count = 0
        for line in raw_text.splitlines():
            line = line.strip().lstrip(',').strip()
            if not line: continue
            
            web_id = None
            full_url = line
            
            m_stream = stream_pattern.search(line)
            m_path = path_pattern.search(line)
            
            if m_stream: web_id = m_stream.group(1)
            elif m_path: web_id = m_path.group(1)
            else:
                if line.startswith('http'): web_id = line
            
            if web_id and web_id not in existing_ids:
                if m_path:
                    name = web_id.split('|')[-1] if '|' in web_id else web_id.split('\\')[-1]
                    name = requests.utils.unquote(name)
                else:
                    name = f"PI_Tag_{added_count + 1}"
                
                self.pi_tags.append({'name': name, 'webId': web_id, 'alias': name, 'stream_url': full_url})
                existing_ids.add(web_id)
                added_count += 1

        if added_count == 0:
            QMessageBox.warning(self, "No URLs Found", "No valid PI stream URLs were detected.")
        else:
            self._refresh_pi_tags_tree()
            self._save_selections()
            QMessageBox.information(self, "URLs Imported", f"Added {added_count} PI tags from stream URLs.")

    def _import_pi_tags_from_csv(self):
        f, _ = QFileDialog.getOpenFileName(self, "Import PI Tags CSV", "", "CSV (*.csv)")
        if not f: return
            
        try:
            stream_pattern = re.compile(r'https?://[^/]+/piwebapi/streams/([^/]+)/value', re.IGNORECASE)
            path_pattern = re.compile(r'https?://[^/]+/[^/]+/[^/]+/data\?path=(.+)', re.IGNORECASE)
            
            with open(f, 'r', encoding='utf-8-sig') as file:
                content = file.read(4096)
                file.seek(0)
                dialect = csv.Sniffer().sniff(content) if content else csv.excel
                has_header = csv.Sniffer().has_header(content) if content else False
                
                reader = csv.reader(file, dialect)
                if has_header: next(reader)
                
                added_count = 0
                existing_ids = {t['webId'] for t in self.pi_tags}
                
                for row in reader:
                    if not row: continue
                    raw_url = row[0].strip()
                    if not raw_url: continue
                    
                    alias = row[1].strip() if len(row) > 1 and row[1].strip() else None
                    name = row[2].strip() if len(row) > 2 and row[2].strip() else None
                    
                    web_id = None
                    full_url = raw_url
                    
                    m_stream = stream_pattern.search(raw_url)
                    m_path = path_pattern.search(raw_url)
                    
                    if m_stream: web_id = m_stream.group(1)
                    elif m_path: web_id = m_path.group(1)
                    else: web_id = raw_url 
                    
                    if web_id and web_id not in existing_ids:
                        if not name:
                            if m_path:
                                name = web_id.split('|')[-1] if '|' in web_id else web_id.split('\\')[-1]
                                name = requests.utils.unquote(name)
                            else:
                                name = f"Imported_{added_count + 1}"
                        
                        if not alias: alias = name
                            
                        self.pi_tags.append({
                            'name': name, 'webId': web_id, 'alias': alias, 
                            'stream_url': full_url if full_url.startswith('http') else None
                        })
                        existing_ids.add(web_id)
                        added_count += 1
                        
            self._refresh_pi_tags_tree()
            self._save_selections()
            QMessageBox.information(self, "Import Successful", f"Imported {added_count} PI tags from CSV.")
        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to import CSV: {e}")

    def _export_pi_tags_template(self):
        f, _ = QFileDialog.getSaveFileName(self, "Export PI CSV Template", "pi_tags_template.csv", "CSV (*.csv)")
        if f:
            try:
                with open(f, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["URL or WebID", "Alias (Influx Field Name)", "Tag Name (Display)"])
                QMessageBox.information(self, "Success", "Template exported.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export template: {e}")

    def start_pi_gateway(self):
        if not self.pi_tags: return QMessageBox.warning(self, "No PI Tags", "Add PI tags first using Search.")
        self.start_pi_button.setEnabled(False)
        self.stop_pi_button.setEnabled(True)
        conf = {
            'url': self.influx_url_input.text(), 'token': self.influx_token_input.text(),
            'org': self.influx_org_input.text(), 'bucket': self.influx_bucket_input.text()
        }
        self.pi_worker = PIInfluxWorker(
            pi_url=self.pi_url_input.text(), pi_user=self.pi_username_input.text(),
            pi_password=self.pi_password_input.text(), influx_config=conf,
            pi_tags=list(self.pi_tags), interval_sec=self.pi_interval_spin.value(),
            use_api_key=self.pi_use_api_key_chk.isChecked(), pi_api_key=self.pi_api_key_input.text(),
            db_measurement=self.pi_measurement_input.text()
        )
        self.pi_worker.log_message.connect(self.log_widget.appendPlainText)
        self.pi_worker.data_written.connect(lambda x: self.status_bar.showMessage(x, 2000))
        self.pi_worker.live_data_update.connect(self._on_pi_live_update)
        self.pi_worker.worker_finished.connect(self.stop_pi_gateway)
        self.pi_worker.start()

    def stop_pi_gateway(self):
        self.stop_pi_button.setEnabled(False)
        if self.pi_worker:
            try: self.pi_worker.log_message.disconnect()
            except: pass
            self.pi_worker.stop()
            self.pi_worker = None
        self.start_pi_button.setEnabled(True)

    @pyqtSlot(dict)
    def _on_live_data_update(self, updates_dict):
        # Only updates the OPC UA window
        for nodeid, value in updates_dict.items():
            item = self.tag_item_map.get(nodeid)
            if item:
                val_str = f"{value:.3f}" if isinstance(value, float) else str(value)
                item.setText(4, val_str)

    @pyqtSlot(dict)
    def _on_pi_live_update(self, updates_dict):
        # Only updates the OSI PI window
        for web_id, value in updates_dict.items():
            item = self.pi_tag_item_map.get(web_id)
            if item: 
                val_str = f"{value:.3f}" if isinstance(value, float) else str(value)
                item.setText(3, val_str)

    def _on_tag_name_changed(self, item, column):
        if column != 0: return
        nid = item.data(1, Qt.ItemDataRole.UserRole)
        if not nid: return
        new_name = item.text(0).strip()
        if not new_name:
            item.setText(0, self.selected_opc_tags.get(nid, nid))
            return
        self.selected_opc_tags[nid] = new_name
        self._save_selections()
        self.status_bar.showMessage(f"✏️ Renamed → '{new_name}'", 3000)

    def _update_write_combo(self):
        has_output = self.write_tag_combo.count() > 0
        self.write_tag_combo.setEnabled(has_output)
        self.write_button.setEnabled(has_output and bool(self.opc_client))

    def _toggle_tag_type(self):
        for item in self.selected_tags_tree.selectedItems():
            nid = item.data(1, Qt.ItemDataRole.UserRole)
            if nid in self.output_tags:
                self.output_tags.remove(nid)
            else:
                self.output_tags.add(nid)
        self._update_selected_tags_list_widget()
        self._save_selections()

    def _remove_selected_tags(self):
        for item in self.selected_tags_tree.selectedItems():
            nid = item.data(1, Qt.ItemDataRole.UserRole)
            if nid in self.selected_opc_tags: del self.selected_opc_tags[nid]
            if nid in self.tag_metadata: del self.tag_metadata[nid]
            if nid in self.output_tags: self.output_tags.remove(nid)
        self._update_selected_tags_list_widget()
        self._save_selections()

    def _clear_all_tags(self):
        self.selected_opc_tags = {}
        self.output_tags = set()
        self.tag_metadata = {}
        self._update_selected_tags_list_widget()
        self._save_selections()

    def _import_tags_from_csv(self):
        f, _ = QFileDialog.getOpenFileName(self, "Import OPC Tags CSV", "", "CSV (*.csv)")
        if not f: return
        try:
            with open(f, 'r', encoding='utf-8-sig') as file:
                content = file.read(4096)
                file.seek(0)
                dialect = csv.Sniffer().sniff(content) if content else csv.excel
                has_header = csv.Sniffer().has_header(content) if content else False
                
                reader = csv.reader(file, dialect)
                if has_header: next(reader)
                
                added_count = 0
                for row in reader:
                    if not row or len(row) < 1: continue
                    nid = row[0].strip()
                    name = row[1].strip() if len(row) > 1 and row[1].strip() else nid
                    mode_str = row[2].strip() if len(row) > 2 else "Input"
                    tag_type = row[3].strip() if len(row) > 3 else "Float"
                    
                    if nid:
                        self.selected_opc_tags[nid] = name
                        self.tag_metadata[nid] = {"type": tag_type}
                        if mode_str.lower() == "output":
                            self.output_tags.add(nid)
                        else:
                            if nid in self.output_tags: self.output_tags.remove(nid)
                        added_count += 1
                
                self._update_selected_tags_list_widget()
                self._save_selections()
                self.status_bar.showMessage(f"✅ Imported {added_count} OPC tags.", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to import CSV: {e}")

    def _export_tags_to_csv(self):
        f, _ = QFileDialog.getSaveFileName(self, "Export OPC Tags CSV", "opc_tags_export.csv", "CSV (*.csv)")
        if f:
            try:
                with open(f, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["NodeID", "Name", "Mode", "DataType"])
                    for nid, name in self.selected_opc_tags.items():
                        mode_str = "Output" if nid in self.output_tags else "Input"
                        meta = self.tag_metadata.get(nid, {"type": "Float"})
                        dtype = meta.get("type", "Float")
                        writer.writerow([nid, name, mode_str, dtype])
                QMessageBox.information(self, "Success", f"Exported {len(self.selected_opc_tags)} tags.")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export CSV: {e}")

    def _load_csv_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Load CSV", "", "CSV (*.csv)")
        if f:
            self.csv_file_path = f
            self.csv_path_line_edit.setText(f)
            self.start_simulator_button.setEnabled(True)
            self._save_selections()

    def export_log(self):
        f, _ = QFileDialog.getSaveFileName(self, "Save Log", "", "Text (*.txt)")
        if f:
            with open(f, 'w') as file: file.write(self.log_widget.toPlainText())

    def start_api(self):
        self.start_api_button.setEnabled(False)
        self.stop_api_button.setEnabled(True)
        self.api_worker = APIWorker(self.api_port_input.value(), lambda: self.opc_client)
        self.api_worker.log_message.connect(self.log_widget.appendPlainText)
        self.api_worker.start()

    def stop_api(self):
        self.stop_api_button.setEnabled(False)
        if self.api_worker:
            self.api_worker.stop()
            self.api_worker = None
        self.start_api_button.setEnabled(True)

    def closeEvent(self, e):
        # Prevent UI freezing on close! Immediately exits the Python process.
        self.status_bar.showMessage("Shutting down...", 5000)
        QApplication.processEvents()
        os._exit(0)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet("""
        QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
        }
        QGroupBox {
            border: 1px solid #45475a;
            border-radius: 6px;
            margin-top: 10px;
            padding-top: 6px;
            font-weight: bold;
            color: #89b4fa;
            font-size: 13px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 8px;
            padding: 0 4px;
        }
        QPushButton {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            border-radius: 5px;
            padding: 5px 12px;
            font-size: 13px;
        }
        QPushButton:hover {
            background-color: #45475a;
            border: 1px solid #89b4fa;
        }
        QPushButton:pressed {
            background-color: #585b70;
        }
        QPushButton:disabled {
            background-color: #1e1e2e;
            color: #6c7086;
            border: 1px solid #313244;
        }
        QLineEdit, QSpinBox, QComboBox {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 4px 6px;
            font-size: 13px;
        }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
            border: 1px solid #89b4fa;
        }
        QCheckBox, QRadioButton {
            color: #cdd6f4;
            font-size: 13px;
            spacing: 6px;
        }
        QCheckBox::indicator, QRadioButton::indicator {
            width: 16px;
            height: 16px;
        }
        QCheckBox:disabled {
            color: #6c7086;
        }
        QTreeWidget {
            background-color: #181825;
            color: #cdd6f4;
            border: 1px solid #45475a;
            alternate-background-color: #1e1e2e;
            font-size: 13px;
        }
        QTreeWidget::item:selected {
            background-color: #89b4fa;
            color: #1e1e2e;
        }
        QHeaderView::section {
            background-color: #313244;
            color: #89b4fa;
            border: 1px solid #45475a;
            padding: 4px;
            font-weight: bold;
        }
        QPlainTextEdit {
            background-color: #181825;
            color: #a6e3a1;
            border: 1px solid #45475a;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12px;
        }
        QLabel {
            color: #cdd6f4;
            font-size: 13px;
        }
        QScrollBar:vertical {
            background: #1e1e2e;
            width: 10px;
        }
        QScrollBar::handle:vertical {
            background: #45475a;
            border-radius: 5px;
        }
        QSplitter::handle {
            background: #45475a;
        }
        QStatusBar {
            background-color: #181825;
            color: #a6e3a1;
        }
    """)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    w = MainWindow()
    w.show()
    with loop: loop.run_forever()