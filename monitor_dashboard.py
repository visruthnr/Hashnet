import subprocess
import re
import hashlib
import platform
from datetime import datetime
import ipaddress
import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh
import os

# ---------------- Device Monitor ----------------


class DeviceMonitor:
    def __init__(self):
        self.devices = {}  # MAC → device info
        self.os_type = platform.system()
        self.subnet = ipaddress.ip_network("192.168.137.0/24")
        self.gateway_ip = "192.168.137.1"
        self.broadcast_ip = "192.168.137.255"
        self.timeout_seconds = 20  # Remove devices not seen for 20s

    def get_mac_ip_map(self):
        mapping = {}
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":").upper()
                        if re.match(r"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$", mac):
                            try:
                                ip_obj = ipaddress.ip_address(ip)
                                if ip_obj in self.subnet and ip != self.gateway_ip and ip != self.broadcast_ip:
                                    mapping[ip] = mac
                            except ValueError:
                                pass
        except Exception as e:
            st.error(f"Error reading ARP: {e}")
        return mapping

    def ping(self, ip):
        """Check if IP is alive"""
        param = "-n" if platform.system() == "Windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", param, "1", "-w", "1000", ip],
                capture_output=True
            )
            return result.returncode == 0
        except:
            return False

    def generate_hash(self, ip, mac):
        unique_string = f"{ip}{mac}".encode("utf-8")
        return hashlib.sha256(unique_string).hexdigest()

    def update_devices(self):
        current_time = datetime.now()
        mac_ip_map = self.get_mac_ip_map()

        # Only include devices that respond to ping
        live_devices = {}
        for ip, mac in mac_ip_map.items():
            if self.ping(ip):
                device_hash = self.generate_hash(ip, mac)
                live_devices[mac] = {
                    "MAC": mac,
                    "Hash": device_hash,
                    "IP": ip,  # Internal only
                    "Last Seen": current_time
                }

        # Remove stale devices based on timeout
        to_remove = []
        for mac, info in self.devices.items():
            if (current_time - info["Last Seen"]).total_seconds() > self.timeout_seconds:
                to_remove.append(mac)
        for mac in to_remove:
            del self.devices[mac]

        # Merge live devices
        self.devices.update(live_devices)

        # Prepare list for display
        devices_list = []
        for info in self.devices.values():
            devices_list.append({
                "MAC": info["MAC"],
                "Hash": info["Hash"],
                "Last Seen": info["Last Seen"].strftime("%H:%M:%S"),
                "IP": info["IP"]  # Keep internally
            })
        return devices_list


# ---------------- Persistent Admin Storage ----------------
ADMIN_FILE = "admin_assignments.csv"


def load_admin_map():
    if os.path.exists(ADMIN_FILE):
        df = pd.read_csv(ADMIN_FILE, index_col=0)
        return df.to_dict(orient="index")
    return {}


def save_admin_map(admin_map):
    df = pd.DataFrame.from_dict(admin_map, orient="index")
    df.to_csv(ADMIN_FILE)


# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="Hotspot Device Monitor", layout="wide")
st.title("📡 Wi-Fi Hotspot Device Monitor")
st.caption("Live view of devices connected to your Windows Hotspot")

monitor = DeviceMonitor()
refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 5, 60, 10)

# Auto-refresh
st_autorefresh(interval=refresh_interval*1000, key="refresh")

# Load persistent admin mapping
if "admin_map" not in st.session_state:
    # MAC → {"Name":..., "Role":...}
    st.session_state.admin_map = load_admin_map()

# Update devices
devices = monitor.update_devices()


# Role options
role_options = ["Student", "Adult", "Child", "Guest"]

# Admin panel for assigning Name/Role
st.subheader("🛠 Assign Name and Role to Devices")
for device in devices:
    mac = device["MAC"]
    if mac not in st.session_state.admin_map:
        st.session_state.admin_map[mac] = {"Name": "", "Role": role_options[0]}

    cols = st.columns([2, 2, 1])
    with cols[0]:
        st.text(f"{mac}")
    with cols[1]:
        st.session_state.admin_map[mac]["Name"] = st.text_input(
            f"Name ({mac})",
            value=st.session_state.admin_map[mac]["Name"], key=f"name_{mac}"
        )
    with cols[2]:
        st.session_state.admin_map[mac]["Role"] = st.selectbox(
            f"Role ({mac})",
            options=role_options,
            index=role_options.index(st.session_state.admin_map[mac]["Role"])
            if st.session_state.admin_map[mac]["Role"] in role_options else 0,
            key=f"role_{mac}"
        )

# Save admin mapping persistently
save_admin_map(st.session_state.admin_map)

# Merge admin mapping with device table
for device in devices:
    mac = device["MAC"]
    if mac in st.session_state.admin_map:
        device["Name"] = st.session_state.admin_map[mac]["Name"]
        device["Role"] = st.session_state.admin_map[mac]["Role"]
    else:
        device["Name"] = ""
        device["Role"] = ""

# Display table WITHOUT IP
if devices:
    df = pd.DataFrame(devices)
    df = df[["MAC", "Name", "Role", "Hash", "Last Seen"]]  # IP hidden
    st.dataframe(df)
else:
    st.warning("⚠️ No devices found")

st.text(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
