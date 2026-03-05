import sys
import os
import asyncio
import logging
import json
import csv
import time
import re
from datetime import datetime, timezone

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
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

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
        try:
            await client.set_security(
                SecurityPolicyBasic256Sha256,
                certificate=cert_path,
                private_key=key_path
            )
        except Exception as e:
            logging.warning(f"Cert security SignAndEncrypt failed, trying Sign: {e}")
            try:
                await client.set_security(SecurityPolicyBasic256Sha256, certificate=cert_path)
            except Exception as e2:
                logging.warning(f"Cert security Sign also failed, connecting without cert: {e2}")

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
            "DB_BUCKET": "Bucket Name", "DB_MEASUREMENT": "Read Measurement",
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

        btn_layout = QHBoxLayout()
        self.select_button = QPushButton("Add Selected Tags")
        self.select_button.clicked.connect(self._add_selected_tags)
        btn_layout.addWidget(self.select_button)
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        btn_layout.addWidget(self.close_button)
        self.layout.addLayout(btn_layout)
        self.selected_node_ids = set()

    async def populate_tree(self, client, existing_selections_nodeids=None):
        self.tree.clear()
        self.selected_node_ids.clear()
        if existing_selections_nodeids:
            self.selected_node_ids.update(existing_selections_nodeids)
        try:
            root_node = client.get_objects_node()
            root_item = QTreeWidgetItem(self.tree, ["Objects", "i=85", "", ""])
            await self.add_children_to_tree(client, root_node, root_item)
            root_item.setExpanded(True)
        except Exception as e:
            logging.error(f"Browser Error: {e}")

    async def add_children_to_tree(self, client, parent_node, parent_item):
        try:
            children = await parent_node.get_children()
            for child in children:
                display_name = await child.read_display_name()
                node_id = child.nodeid.to_string()
                node_class = await child.read_node_class()

                item = QTreeWidgetItem(parent_item, [display_name.Text, node_id, node_class.name, ""])
                if node_class == ua.NodeClass.Variable:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(0,
                                       Qt.CheckState.Checked if node_id in self.selected_node_ids else Qt.CheckState.Unchecked)
                elif node_class == ua.NodeClass.Object:
                    await self.add_children_to_tree(client, child, item)
        except:
            pass

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


# --- WORKER: OPC UA -> INFLUXDB ---
class OPCInfluxWorker(QThread):
    log_message = pyqtSignal(str)
    connection_status = pyqtSignal(bool)
    worker_finished = pyqtSignal()
    data_written = pyqtSignal(str)
    live_data_update = pyqtSignal(str, object)  # UI Signal

    def __init__(self, opc_config, influx_config, selected_tags_nodeids, write_mode, interval_ms):
        super().__init__()
        self.opc_config = opc_config
        self.influx_config = influx_config
        self.selected_tags_nodeids = selected_tags_nodeids
        self.write_mode = write_mode
        self.interval_ms = interval_ms
        self._is_running = True
        self.db_measurement = getattr(config, 'DB_MEASUREMENT', 'kiln1') if config else 'kiln1'

    def stop(self):
        self._is_running = False
        self.log_message.emit("Stopping Gateway...")

    async def run_process(self):
        client = Client(url=self.opc_config['url'])
        await setup_opc_security(client, self.opc_config)
        
        influx = InfluxDBClient(url=self.influx_config['url'], token=self.influx_config['token'],
                                org=self.influx_config['org'])
        write_api = influx.write_api(write_options=SYNCHRONOUS)

        try:
            await asyncio.wait_for(client.connect(), timeout=10.0)
            self.log_message.emit(f"Connected to {self.opc_config['url']}")
            self.connection_status.emit(True)

            nodes = [client.get_node(nid) for nid in self.selected_tags_nodeids]

            while self._is_running:
                try:
                    values = await client.get_values(nodes)
                    timestamp = datetime.now(timezone.utc)
                    point = Point(self.db_measurement).time(timestamp, WritePrecision.NS)

                    log_samples = []
                    for i, val in enumerate(values):
                        nid = self.selected_tags_nodeids[i]

                        try:
                            if isinstance(val, bool):
                                final_val = val
                            else:
                                final_val = float(val)
                        except (ValueError, TypeError):
                            final_val = str(val)

                        point.field(nid, final_val)

                        # Emit to UI
                        self.live_data_update.emit(nid, final_val)

                        if i < 3: log_samples.append(f"{nid}={final_val}")

                    write_api.write(bucket=self.influx_config['bucket'], org=self.influx_config['org'], record=point)
                    self.data_written.emit(f"✅ Live: {', '.join(log_samples)}...")
                except Exception as e:
                    self.log_message.emit(f"Read Error: {e}")

                await asyncio.sleep(self.interval_ms / 1000.0)

        except Exception as e:
            self.log_message.emit(f"Connection Failed: {e}")
            self.connection_status.emit(False)
        finally:
            await client.disconnect()
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

    def __init__(self, opc_config, influx_config, allowed_setpoints_map):
        super().__init__()
        self.opc_config = opc_config
        self.influx_config = influx_config
        self.allowed_setpoints_map = allowed_setpoints_map
        self.valid_node_ids = set(allowed_setpoints_map.values())
        self.running = True
        self.influx_bucket = influx_config.get('bucket', 'kiln_process_data')
        self.write_back_meas = 'kiln2'

    def stop(self):
        self.running = False

    async def run_loop(self):
        client = Client(url=self.opc_config['url'])
        await setup_opc_security(client, self.opc_config)
        influx = InfluxDBClient(
            url=self.influx_config['url'],
            token=self.influx_config['token'],
            org=self.influx_config['org']
        )
        query_api = influx.query_api()

        try:
            await asyncio.wait_for(client.connect(), timeout=10.0)
            self.log_msg.emit(f"Watcher Active on '{self.write_back_meas}'")
            last_ts = None

            while self.running:
                q = f'from(bucket:"{self.influx_bucket}") |> range(start: -1m) |> filter(fn: (r) => r["_measurement"] == "{self.write_back_meas}") |> last()'
                try:
                    tables = query_api.query(q)
                    cmd = {}
                    ts = None
                    for tbl in tables:
                        for rec in tbl.records:
                            ts = rec.get_time()
                            cmd[rec.get_field()] = rec.get_value()

                    if ts and ts != last_ts:
                        last_ts = ts
                        self.log_msg.emit("New Command Received")
                        for nid, val in cmd.items():
                            target_id = self.allowed_setpoints_map.get(nid, nid)
                            if target_id in self.valid_node_ids:
                                node = client.get_node(target_id)
                                await node.write_value(float(val))
                                self.log_msg.emit(f"--> PLC WROTE: {target_id} = {val}")
                except Exception:
                    pass
                await asyncio.sleep(2)
        except Exception as e:
            self.log_msg.emit(f"Watcher Error: {e}")
        finally:
            await client.disconnect()
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
    live_data_update = pyqtSignal(str, object)

    def __init__(self, influx_config, csv_file_path):
        super().__init__()
        self.influx_config = influx_config
        self.csv_file_path = csv_file_path
        self._is_running = True
        self.db_measurement = getattr(config, 'DB_MEASUREMENT', 'kiln1') if config else 'kiln1'

    def stop(self):
        self._is_running = False
        self.log_message.emit("Stopping Simulator...")

    def run(self):
        try:
            client = InfluxDBClient(url=self.influx_config['url'], token=self.influx_config['token'],
                                    org=self.influx_config['org'])
            write_api = client.write_api(write_options=SYNCHRONOUS)

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

                for i, col in enumerate(headers):
                    if i >= len(row): continue
                    raw = row[i].strip()
                    val = None
                    try:
                        val = float(raw)
                    except ValueError:
                        try:
                            val = float(raw.replace(',', '.'))
                        except ValueError:
                            continue

                    point.field(col.strip(), val)
                    # point.tag("node_id", f"sim_{col.strip()}")  <-- Commented out

                    self.live_data_update.emit(col.strip(), val)

                    if len(display) < 3: display.append(f"{col}={val}")
                    valid_row = True

                if valid_row:
                    write_api.write(bucket=self.influx_config['bucket'], org=self.influx_config['org'], record=point)
                    self.data_written.emit(f"✅ Sim Write: {', '.join(display)}...")

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
            if not client:
                raise HTTPException(503, "Not connected to OPC Server")
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
        if self.server:
            self.server.should_exit = True


# --- PI WEB API HELPERS ---
def _pi_get(url, username, password, verify=False):
    """Authenticated GET to PI Web API, returns parsed JSON or raises."""
    resp = requests.get(url, auth=(username, password), verify=verify, timeout=10)
    resp.raise_for_status()
    return resp.json()

def _pi_search_tags(base_url, username, password, query, verify=False):
    """Search PI tags by name query. Returns list of {name, webId} dicts."""
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
    tags_added = pyqtSignal(list)  # list of {name, webId, alias}

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
        if not q:
            return
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
        if selected:
            self.tags_added.emit(selected)
        self.accept()


# --- WORKER: PI WEB API -> INFLUXDB ---
class PIInfluxWorker(QThread):
    log_message = pyqtSignal(str)
    data_written = pyqtSignal(str)
    live_data_update = pyqtSignal(str, object)   # webId, value
    worker_finished = pyqtSignal()

    def __init__(self, pi_url, pi_user, pi_password, influx_config, pi_tags, interval_sec):
        super().__init__()
        self.pi_url = pi_url.rstrip('/')
        self.pi_user = pi_user
        self.pi_password = pi_password
        self.influx_config = influx_config
        # pi_tags: list of {webId, name, alias}
        self.pi_tags = pi_tags
        self.interval_sec = interval_sec
        self._is_running = True
        self.db_measurement = getattr(config, 'DB_MEASUREMENT', 'kiln1') if config else 'kiln1'

    def stop(self):
        self._is_running = False
        self.log_message.emit("Stopping PI Gateway...")

    def run(self):
        try:
            influx = InfluxDBClient(
                url=self.influx_config['url'],
                token=self.influx_config['token'],
                org=self.influx_config['org']
            )
            write_api = influx.write_api(write_options=SYNCHRONOUS)
            self.log_message.emit(f"PI Gateway started → {self.db_measurement}")

            # Build webId → alias map and batch webId list
            web_ids = [t['webId'] for t in self.pi_tags]
            alias_map = {t['webId']: t.get('alias') or t['name'] for t in self.pi_tags}

            while self._is_running:
                try:
                    # Batch value request
                    batch_url = f"{self.pi_url}/streamsets/value"
                    payload = [{'WebId': wid} for wid in web_ids]
                    resp = requests.post(
                        batch_url,
                        json=payload,
                        auth=(self.pi_user, self.pi_password),
                        verify=False,
                        timeout=10
                    )
                    resp.raise_for_status()
                    items = resp.json().get('Items', [])

                    ts = datetime.now(timezone.utc)
                    point = Point(self.db_measurement).time(ts, WritePrecision.NS)
                    log_samples = []

                    for item in items:
                        wid = item.get('WebId', '')
                        val_obj = item.get('Value', {})
                        raw = val_obj.get('Value', val_obj) if isinstance(val_obj, dict) else val_obj
                        alias = alias_map.get(wid, wid)
                        try:
                            val = float(raw)
                        except (ValueError, TypeError):
                            val = str(raw)
                        point.field(alias, val)
                        self.live_data_update.emit(wid, val)
                        if len(log_samples) < 3:
                            log_samples.append(f"{alias}={val}")

                    write_api.write(
                        bucket=self.influx_config['bucket'],
                        org=self.influx_config['org'],
                        record=point
                    )
                    self.data_written.emit(f"✅ PI: {', '.join(log_samples)}...")

                except Exception as e:
                    self.log_message.emit(f"PI Read Error: {e}")

                for _ in range(int(self.interval_sec * 10)):
                    if not self._is_running:
                        break
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
        self.model_setpoints = {}
        self.csv_file_path = self.selections.get("csv_file_path")
        self.tag_item_map = {}
        # PI tags: list of {webId, name, alias}
        self.pi_tags = self.selections.get("pi_tags", [])
        self.pi_tag_item_map = {}  # webId -> QTreeWidgetItem

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
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
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
        self.selections["csv_file_path"] = self.csv_file_path
        self.selections["pi_url"] = self.pi_url_input.text()
        self.selections["pi_username"] = self.pi_username_input.text()
        self.selections["pi_password"] = self.pi_password_input.text()
        self.selections["pi_tags"] = self.pi_tags
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.selections, f, indent=4)
        except:
            pass

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
            with open(path, 'r') as f:
                data = json.load(f)
            self.model_setpoints = {}
            for k, v in data.get("control_variables", {}).items():
                if v.get("is_setpoint"):
                    self.model_setpoints[k] = v.get("tag_name")
                    self.output_tags.add(v.get("tag_name"))
            self.status_bar.showMessage(f"Loaded {len(self.model_setpoints)} setpoints", 4000)
            self.watcher_chk.setEnabled(True)
            self.watcher_chk.setText(f"Enable Automated Write-Back ({len(self.model_setpoints)} tags)")
            self._update_selected_tags_list_widget()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _setup_ui(self):
        self.setCentralWidget(QScrollArea())
        central = QWidget()
        self.centralWidget().setWidget(central)
        self.centralWidget().setWidgetResizable(True)
        layout = QHBoxLayout(central)

        # Left Panel
        left = QVBoxLayout()

        # 1. OPC
        g1 = QGroupBox("1. OPC UA Server Configuration")
        f1 = QFormLayout()
        self.opc_endpoint_input = QLineEdit(self.selections.get("opc_endpoint", "opc.tcp://localhost:4840"))
        self.opc_username_input = QLineEdit(self.selections.get("opc_username", ""))
        self.opc_password_input = QLineEdit(self.selections.get("opc_password", ""))
        self.opc_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        f1.addRow("Endpoint:", self.opc_endpoint_input)
        f1.addRow("Username:", self.opc_username_input)
        f1.addRow("Password:", self.opc_password_input)
        
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
        h1.addWidget(self.connect_opc_button)
        h1.addWidget(self.disconnect_opc_button)
        f1.addRow(h1)
        self.opc_connection_status_label = QLabel("Status: Disconnected")
        f1.addRow(self.opc_connection_status_label)
        g1.setLayout(f1)
        left.addWidget(g1)

        # 2. Influx
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
        self.write_interval_spinbox.setValue(1000)
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

        # 3. Manual Write
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

        # 4. Automated Write-Back
        g4 = QGroupBox("4. Automated Model Write-Back")
        v4 = QVBoxLayout()
        self.watcher_chk = QCheckBox("Enable Automated Write-Back")
        self.watcher_chk.setEnabled(False)
        self.watcher_chk.toggled.connect(self.toggle_write_watcher)
        v4.addWidget(self.watcher_chk)
        self.watcher_status = QLabel("Status: Stopped")
        v4.addWidget(self.watcher_status)
        g4.setLayout(v4)
        left.addWidget(g4)

        # 5. Execution
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

        # 6. Simulator
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

        # 7. FastAPI Write Server
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

        # 8. OSI PI Configuration
        g8 = QGroupBox("8. OSI PI Server (PI Web API)")
        f8 = QFormLayout()
        self.pi_url_input = QLineEdit(self.selections.get("pi_url", "https://mypiserver/piwebapi"))
        self.pi_username_input = QLineEdit(self.selections.get("pi_username", ""))
        self.pi_password_input = QLineEdit(self.selections.get("pi_password", ""))
        self.pi_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        f8.addRow("PI Web API URL:", self.pi_url_input)
        f8.addRow("Username:", self.pi_username_input)
        f8.addRow("Password:", self.pi_password_input)

        h8a = QHBoxLayout()
        self.pi_search_button = QPushButton("🔍 Search PI Tags...")
        self.pi_search_button.clicked.connect(self._open_pi_search)
        self.pi_clear_button = QPushButton("✕ Clear All")
        self.pi_clear_button.clicked.connect(self._clear_pi_tags)
        h8a.addWidget(self.pi_search_button)
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

        # Right Panel
        right = QSplitter(Qt.Orientation.Vertical)

        g_tags = QGroupBox("OPC UA Tags to Monitor")
        l_tags = QVBoxLayout()
        self.selected_tags_tree = QTreeWidget()
        self.selected_tags_tree.setHeaderLabels(["Tag Name", "NodeID", "Type", "Value"])
        self.selected_tags_tree.setColumnWidth(0, 200)
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

        # PI Tags Panel
        g_pi_tags = QGroupBox("OSI PI Tags (PI \u2192 InfluxDB kiln1)")
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

    # --- LOGIC HANDLERS ---
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
            from datetime import timedelta
            
            self.cert_folder.mkdir(exist_ok=True)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"PyQt6 OPC UA Client"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=3650)
            ).sign(private_key, hashes.SHA256())
            
            with open(self.client_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.DER))
                
            with open(self.client_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
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
            await dlg.populate_tree(self.opc_client, self.selected_opc_tags.keys())
            dlg.exec()
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

        # UI RESET
        self.connect_opc_button.setText("🌐 Connect & Browse")
        self.connect_opc_button.setEnabled(True)
        self.disconnect_opc_button.setText("🔌 Disconnect")
        self.disconnect_opc_button.setEnabled(False)
        self.opc_connection_status_label.setText("Status: Disconnected")
        self.opc_connection_status_label.setStyleSheet("color: #f44336; font-weight: bold;")
        self.write_box.setEnabled(False)
        self._update_write_combo()
        if self.stop_gateway_button.isEnabled(): self.stop_gateway()
        self.opc_client_connected.emit(False)
        self.status_bar.showMessage("Disconnected.", 2000)

        # Network Cleanup
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
        self.start_gateway_button.setEnabled(connected)
        self._update_write_combo()

    def start_gateway(self):
        if not self.selected_opc_tags: return QMessageBox.warning(self, "No Tags", "Select tags first")
        self.start_gateway_button.setEnabled(False)
        self.stop_gateway_button.setEnabled(True)
        self.start_simulator_button.setEnabled(False)  # Lock Simulator

        conf = {'url': self.influx_url_input.text(), 'token': self.influx_token_input.text(),
                'org': self.influx_org_input.text(), 'bucket': self.influx_bucket_input.text()}
        self.opc_worker = OPCInfluxWorker(self._get_opc_config(), conf, list(self.selected_opc_tags.keys()),
                                          'per_second', self.write_interval_spinbox.value())
        self.opc_worker.log_message.connect(self.log_widget.appendPlainText)
        self.opc_worker.data_written.connect(lambda x: self.status_bar.showMessage(x, 2000))
        self.opc_worker.live_data_update.connect(self._on_live_data_update)
        self.opc_worker.start()

    def stop_gateway(self):
        self.stop_gateway_button.setEnabled(False)
        if self.opc_worker: self.opc_worker.stop()
        self.start_gateway_button.setEnabled(True)
        self.start_simulator_button.setEnabled(bool(self.csv_file_path))  # Unlock

    # --- PI GATEWAY METHODS ---
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
        if column != 1:
            return
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

    def start_pi_gateway(self):
        if not self.pi_tags:
            return QMessageBox.warning(self, "No PI Tags", "Add PI tags first using Search.")
        self.start_pi_button.setEnabled(False)
        self.stop_pi_button.setEnabled(True)
        conf = {
            'url': self.influx_url_input.text(),
            'token': self.influx_token_input.text(),
            'org': self.influx_org_input.text(),
            'bucket': self.influx_bucket_input.text()
        }
        self.pi_worker = PIInfluxWorker(
            pi_url=self.pi_url_input.text(),
            pi_user=self.pi_username_input.text(),
            pi_password=self.pi_password_input.text(),
            influx_config=conf,
            pi_tags=list(self.pi_tags),
            interval_sec=self.pi_interval_spin.value()
        )
        self.pi_worker.log_message.connect(self.log_widget.appendPlainText)
        self.pi_worker.data_written.connect(lambda x: self.status_bar.showMessage(x, 2000))
        self.pi_worker.live_data_update.connect(self._on_pi_live_update)
        self.pi_worker.start()

    def stop_pi_gateway(self):
        self.stop_pi_button.setEnabled(False)
        if self.pi_worker:
            self.pi_worker.stop()
            self.pi_worker = None
        self.start_pi_button.setEnabled(True)

    @pyqtSlot(str, object)
    def _on_pi_live_update(self, web_id, value):
        item = self.pi_tag_item_map.get(web_id)
        if item:
            item.setText(3, f"{value:.3f}" if isinstance(value, float) else str(value))

    def start_simulator(self):
        self.start_simulator_button.setEnabled(False)
        self.stop_simulator_button.setEnabled(True)
        self.connect_opc_button.setEnabled(False)  # Lock OPC

        conf = {'url': self.influx_url_input.text(), 'token': self.influx_token_input.text(),
                'org': self.influx_org_input.text(), 'bucket': self.influx_bucket_input.text()}
        self.simulator_worker = SimulatorWorker(conf, self.csv_file_path)
        self.simulator_worker.log_message.connect(self.log_widget.appendPlainText)
        self.simulator_worker.data_written.connect(lambda x: self.status_bar.showMessage(x, 2000))
        self.simulator_worker.live_data_update.connect(self._on_live_data_update)
        self.simulator_worker.start()

    def stop_simulator(self):
        self.stop_simulator_button.setEnabled(False)
        if self.simulator_worker: self.simulator_worker.stop()
        self.start_simulator_button.setEnabled(True)
        self.connect_opc_button.setEnabled(True)  # Unlock

    def toggle_write_watcher(self, checked):
        if checked:
            if not self.model_setpoints: return self.watcher_chk.setChecked(False)
            conf = self._get_opc_config()
            influx_conf = {
                'url': self.influx_url_input.text(),
                'token': self.influx_token_input.text(),
                'org': self.influx_org_input.text(),
                'bucket': self.influx_bucket_input.text()
            }
            self.watcher_worker = SetpointWatcherWorker(conf, influx_conf, self.model_setpoints)
            self.watcher_worker.log_msg.connect(self.log_widget.appendPlainText)
            self.watcher_worker.start()
            self.watcher_status.setText("Status: Running")
            self.watcher_status.setStyleSheet("color: #4caf50;")
        else:
            if self.watcher_worker: self.watcher_worker.stop()
            self.watcher_status.setText("Status: Stopped")
            self.watcher_status.setStyleSheet("")

    @qasync.asyncSlot()
    async def _on_write_button_clicked(self):
        nid = self.write_tag_combo.currentData()
        val = self.write_value_input.text()
        if not nid or not val: return

        self.write_button.setEnabled(False)
        try:
            node = self.opc_client.get_node(nid)
            await node.write_value(float(val))
            QMessageBox.information(self, "Success", f"Wrote {val}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
        finally:
            self.write_button.setEnabled(True)

    @qasync.asyncSlot()
    async def test_influxdb_connection(self):
        self.influx_test_button.setEnabled(False)
        try:
            c = InfluxDBClient(url=self.influx_url_input.text(), token=self.influx_token_input.text(),
                               org=self.influx_org_input.text())
            if c.ping():
                self.influx_connection_status_label.setText("Status: Connected")
                self.influx_connection_status_label.setStyleSheet("color: #4caf50;")
            else:
                raise Exception("Ping Failed")
        except Exception as e:
            self.influx_connection_status_label.setText("Status: Failed")
            self.influx_connection_status_label.setStyleSheet("color: #f44336;")
        finally:
            self.influx_test_button.setEnabled(True)

    # --- TAG LIST UTILS ---
    @pyqtSlot(dict)
    def _on_tags_selected(self, tags):
        self.selected_opc_tags.update(tags)
        self._update_selected_tags_list_widget()
        self._save_selections()

    def _update_selected_tags_list_widget(self):
        self.selected_tags_tree.clear()
        self.write_tag_combo.clear()
        self.tag_item_map.clear()
        for nid, name in self.selected_opc_tags.items():
            type_str = "[OUTPUT]" if nid in self.output_tags else "[INPUT]"
            item = QTreeWidgetItem([name, nid, type_str, "---"])
            item.setData(1, Qt.ItemDataRole.UserRole, nid)
            self.selected_tags_tree.addTopLevelItem(item)
            self.tag_item_map[nid] = item
            if nid in self.output_tags: self.write_tag_combo.addItem(f"{name} ({nid})", userData=nid)
        self._update_write_combo()

    @pyqtSlot(str, object)
    def _on_live_data_update(self, nodeid, value):
        if nodeid in self.tag_item_map:
            item = self.tag_item_map[nodeid]
            if isinstance(value, float):
                val_str = f"{value:.3f}"
            else:
                val_str = str(value)
            item.setText(3, val_str)

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
            del self.selected_opc_tags[nid]
            if nid in self.output_tags: self.output_tags.remove(nid)
        self._update_selected_tags_list_widget()
        self._save_selections()

    def _clear_all_tags(self):
        self.selected_opc_tags = {}
        self.output_tags = set()
        self._update_selected_tags_list_widget()
        self._save_selections()

    def _import_tags_from_csv(self):
        f, _ = QFileDialog.getOpenFileName(self, "Import CSV", "", "CSV (*.csv)")
        if f:
            try:
                with open(f, 'r') as file:
                    reader = csv.reader(file)
                    for row in reader:
                        if len(row) >= 1: self.selected_opc_tags[row[0]] = row[1] if len(row) > 1 else row[0]
                self._update_selected_tags_list_widget()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _export_tags_to_csv(self):
        f, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV (*.csv)")
        if f:
            try:
                with open(f, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["NodeID", "Name", "Type"])
                    for nid, name in self.selected_opc_tags.items():
                        writer.writerow([nid, name, "Output" if nid in self.output_tags else "Input"])
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

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
        if self.opc_worker: self.opc_worker.stop()
        if self.simulator_worker: self.simulator_worker.stop()
        if self.watcher_worker: self.watcher_worker.stop()
        if hasattr(self, 'api_worker') and self.api_worker: self.api_worker.stop()
        if self.opc_client:
            pass
        self._save_selections()
        e.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    w = MainWindow()
    w.show()
    with loop: loop.run_forever()