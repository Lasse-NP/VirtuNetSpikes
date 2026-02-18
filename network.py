#!/usr/bin/env python3
"""
Mininet Virtual Network with OS Fingerprint Spoofing
Builds a virtual network of hosts with different OS fingerprints, scannable by Nmap.

Requirements:
  sudo apt install mininet nmap python3-pip
  sudo pip3 install mininet

Usage:
  sudo python3 network.py [--topo star|linear|tree] [--verbose]
"""

import argparse
import sys
import os
import time
import subprocess
import threading
import re
import shlex
import tempfile
import shutil

from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.link import Link
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.topo import Topo

# ── OS Fingerprint profiles ────────────────────────────────────────────────────
# Each profile defines:
# ttl        : IP TTL value (Linux≈64, Windows≈128, Cisco≈255, BSD≈64)
# tcp_window : TCP window size
# os_label   : human-readable label
# services   : list of (port, protocol, banner) tuples to open
OS_PROFILES = {
    "windows_server_2019": {
        "ttl": 128,
        "tcp_window": 65535,
        "os_label": "Windows Server 2019",
        "services": [
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135, "raw", ""),  # RPC endpoint mapper
            (139, "raw", ""),  # NetBIOS
            (445, "raw", ""),  # SMB
            (3389, "raw", ""), # RDP
        ],
    },
    "ubuntu_22": {
        "ttl": 64,
        "tcp_window": 29200,
        "os_label": "Ubuntu 22.04 LTS",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"),
            (3306, "raw", ""),  # MySQL
        ],
    },
    "centos_7": {
        "ttl": 64,
        "tcp_window": 14600,
        "os_label": "CentOS 7",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_7.4\r\n"),
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (CentOS)\r\nContent-Length: 0\r\n\r\n"),
            (443, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (CentOS)\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "cisco_ios": {
        "ttl": 255,
        "tcp_window": 4128,
        "os_label": "Cisco IOS 15.x",
        "services": [
            (23, "raw", "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"), # Telnet IAC
            (80, "http", "HTTP/1.1 200 OK\r\nServer: cisco-IOS\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "freebsd_13": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "FreeBSD 13",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_9.0 FreeBSD-20221006\r\n"),
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (FreeBSD)\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "android_device": {
        "ttl": 64,
        "tcp_window": 65700,
        "os_label": "Android 12",
        "services": [
            (5555, "raw", "CNXN\x00\x00\x00\x01"),  # ADB banner
            (8080, "http", "HTTP/1.1 200 OK\r\nServer: BaseHTTP/0.6 Python/3.10\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "macos_ventura": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "macOS Ventura 13",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_9.0\r\n"),
            (548, "raw", ""),  # AFP
            (5900, "raw", "RFB 003.889\n"),  # VNC
        ],
    },
    "windows_10": {
        "ttl": 128,
        "tcp_window": 64240,
        "os_label": "Windows 10",
        "services": [
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135, "raw", ""),
            (445, "raw", ""),
        ],
    },
}

# ── Topology definitions ───────────────────────────────────────────────────────
class StarTopo(Topo):
    """All hosts connected to a single switch."""
    def build(self, n_hosts=8):
        switch = self.addSwitch("s1")
        for i in range(1, n_hosts + 1):
            host = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(host, switch)

class LinearTopo(Topo):
    """Hosts connected in a chain: h1-s1-s2-h2 ..."""
    def build(self, n_hosts=8):
        switches = []
        for i in range(1, n_hosts + 1):
            s = self.addSwitch(f"s{i}")
            switches.append(s)
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s)
        for i in range(len(switches) - 1):
            self.addLink(switches[i], switches[i + 1])

class TreeTopo(Topo):
    """Two-tier tree: core switch → edge switches → hosts."""
    def build(self, n_hosts=8):
        core = self.addSwitch("s0")
        edge1 = self.addSwitch("s1")
        edge2 = self.addSwitch("s2")
        self.addLink(core, edge1)
        self.addLink(core, edge2)
        half = n_hosts // 2
        for i in range(1, half + 1):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, edge1)
        for i in range(half + 1, n_hosts + 1):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, edge2)

# ── Service emulation ──────────────────────────────────────────────────────────
LISTENER_SCRIPT = """\
#!/usr/bin/env python3
import socket, threading, sys, os, signal
banner = {banner!r}
port = {port}

def handle(conn):
    try:
        if banner:
            conn.sendall(banner if isinstance(banner, bytes) else banner.encode())
        conn.recv(1024)
    except Exception:
        pass
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', port))
server.listen(50)

def stopper(sig, frame):
    server.close()
    sys.exit(0)

signal.signal(signal.SIGTERM, stopper)
signal.signal(signal.SIGINT, stopper)

while True:
    try:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except OSError:
        break
"""

def apply_os_fingerprint(host, profile):
    """
    Apply kernel-level tweaks to make a Mininet host respond with a given
    OS fingerprint (TTL, TCP window size, TCP options).
    """
    ttl = profile["ttl"]
    window = profile["tcp_window"]
    label = profile["os_label"]

    info(f" [*] {host.name}: applying fingerprint → {label}\n")

    # Set default TTL
    host.cmd(f"sysctl -w net.ipv4.ip_default_ttl={ttl}")
    # TCP window / rmem
    host.cmd(f"sysctl -w net.ipv4.tcp_rmem='4096 {window} {window * 4}'")
    host.cmd(f"sysctl -w net.core.rmem_default={window}")
    host.cmd(f"sysctl -w net.core.rmem_max={window * 4}")
    # Disable timestamps for some profiles (Windows-style)
    if ttl == 128:
        host.cmd("sysctl -w net.ipv4.tcp_timestamps=0")
        host.cmd("sysctl -w net.ipv4.tcp_sack=1")
    else:
        host.cmd("sysctl -w net.ipv4.tcp_timestamps=1")
    # Enable ICMP responses
    host.cmd("sysctl -w net.ipv4.icmp_echo_ignore_all=0")

def start_services(host, profile, tmp_dir):
    """Spawn a tiny TCP listener for every service in the profile."""
    pids = []
    for svc in profile["services"]:
        port, proto, banner = svc
        script_path = os.path.join(tmp_dir, f"{host.name}_port{port}.py")
        script = LISTENER_SCRIPT.format(banner=banner, port=port)
        with open(script_path, "w") as f:
            f.write(script)
        pid = host.cmd(f"python3 {script_path} &>/tmp/{host.name}_{port}.log & echo $!")
        pid = pid.strip()
        if pid.isdigit():
            pids.append(int(pid))
        info(f" → {host.name}:{port}/{proto} (pid {pid})\n")
    return pids

# ── Networking helpers (robust detection; no route deletion) ───────────────────
def run(cmd):
    """Run command, return stdout (str)."""
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True).stdout.strip()

def wait_for_default_route(timeout=8, interval=0.5):
    """Wait until a default route appears (up to timeout seconds). Return True/False."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if run("ip route show default"):
            return True
        time.sleep(interval)
    return False

def detect_iface_via_route_get(target_ip="1.1.1.1"):
    """
    Try 'ip route get <target>' and parse 'dev XXX', 'src Y.Y.Y.Y', and 'via Z.Z.Z.Z' (optional).
    Returns (iface, src_ip, via_gateway_or_None) or (None, None, None) on failure.
    """
    out = run(f"ip route get {target_ip}")
    if not out:
        return None, None, None
    parts = out.split()
    iface = parts[parts.index("dev")+1] if "dev" in parts else None
    src_ip = parts[parts.index("src")+1] if "src" in parts else None
    via = parts[parts.index("via")+1] if "via" in parts else None
    return iface, src_ip, via

def detect_iface_with_ipv4():
    """
    Return the first non-virtual iface that has a global IPv4 and carrier (avoid lo, docker*, veth*, virbr*, ovs*).
    """
    lines = run("ip -o -4 addr show scope global").splitlines()
    for line in lines:
        # Example: "2: enp0s3    inet 192.168.0.27/24 brd 192.168.0.255 scope global dynamic enp0s3"
        cols = line.split()
        iface = cols[1]
        if iface.startswith(("lo", "docker", "veth", "virbr", "ovs")):
            continue
        link = run(f"cat /sys/class/net/{iface}/operstate") or "unknown"
        if link.strip() in ("up", "unknown"):  # 'unknown' for some virt drivers
            m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)\b", line)
            if m:
                return iface, m.group(1), int(m.group(2))
    return None, None, None

def get_iface_ipv4_and_prefix(iface):
    out = run(f"ip -o -4 addr show dev {iface}")
    m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)\b", out)
    if not m:
        return None, None
    return m.group(1), int(m.group(2))

def get_default_gateway_for_iface(iface):
    """
    Try to find a default route line that mentions this iface. Return gw or None.
    """
    for line in run("ip route show default").splitlines():
        if f" dev {iface} " in f" {line} ":
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via")+1]
    return None

def save_iptables_state():
    """Save current iptables rules to a temp file; return path."""
    rules = subprocess.run(["iptables-save"], capture_output=True, text=True).stdout
    path = tempfile.mkstemp(prefix="mininet_iptables_", suffix=".save")[1]
    with open(path, "w") as f:
        f.write(rules)
    return path

def restore_iptables_state(path):
    """Restore iptables rules from a file, if present."""
    if path and os.path.exists(path):
        subprocess.run(["iptables-restore", path], capture_output=True, text=True)

# ── Main ───────────────────────────────────────────────────────────────────────
def build_network(topo_name="star", verbose=False):
    if os.geteuid() != 0:
        error("ERROR: This script must be run as root (sudo).\n")
        sys.exit(1)

    setLogLevel("info" if verbose else "warning")

    profiles = list(OS_PROFILES.items())
    n_hosts = len(profiles)
    info(f"\n[+] Building '{topo_name}' topology with {n_hosts} hosts\n")

    # Select topology
    if topo_name == "star":
        topo = StarTopo(n_hosts=n_hosts)
    elif topo_name == "linear":
        topo = LinearTopo(n_hosts=n_hosts)
    else:
        topo = TreeTopo(n_hosts=n_hosts)

    # OVSSwitch in standalone mode (no controller) → normal L2 behaviour
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,  # No OpenFlow controller
        autoSetMacs=True,
    )

    # Keep resources we may need to restore in cleanup
    tmp_dir = tempfile.mkdtemp(prefix="mininet_services_")
    iptables_save_path = None
    host_map = {}
    VM_IFACE = None
    orig_ip = None
    orig_prefix = None
    orig_gw = None
    primary_switch = None

    try:
        net.start()

        # Configure every switch to use normal L2 forwarding
        for switch in net.switches:
            info(f"[+] Setting {switch.name} to standalone mode with NORMAL forwarding\n")
            subprocess.run(["ovs-vsctl", "del-controller", switch.name], check=False)
            subprocess.run(["ovs-vsctl", "set-fail-mode", switch.name, "standalone"], check=False)
            subprocess.run(["ovs-ofctl", "del-flows", switch.name], check=False)
            subprocess.run(["ovs-ofctl", "add-flow", switch.name, "priority=0,actions=NORMAL"], check=False)

        # ── Robust detection of primary interface/IP/gateway (bridged mode) ──
        wait_for_default_route(timeout=8, interval=0.5)  # don't block too long

        VM_IFACE, detected_ip, gw_via = detect_iface_via_route_get("1.1.1.1")
        if VM_IFACE and detected_ip:
            orig_ip = detected_ip
            ip_pref = get_iface_ipv4_and_prefix(VM_IFACE)
            if ip_pref and ip_pref[1] is not None:
                orig_prefix = ip_pref[1]
            orig_gw = gw_via or get_default_gateway_for_iface(VM_IFACE)
        else:
            VM_IFACE, orig_ip, orig_prefix = detect_iface_with_ipv4()
            if not VM_IFACE:
                raise RuntimeError("Could not detect a primary interface with IPv4. Is the bridged NIC up and configured?")
            orig_gw = get_default_gateway_for_iface(VM_IFACE)

        info(f"\n[+] Primary interface: {VM_IFACE}\n")
        info(f"[+] Address on {VM_IFACE}: {orig_ip}/{orig_prefix}\n")
        if orig_gw:
            info(f"[+] Default gateway (detected): {orig_gw}\n")
        else:
            info("[!] No default gateway detected yet. Route changes will be skipped.\n")

        # Determine which OVS switch to use for bridging (first switch)
        primary_switch = net.switches[0].name
        info(f"[+] Using primary switch for bridging: {primary_switch}\n")

        # For visibility
        result = subprocess.run(["ip", "-4", "addr", "show", "dev", VM_IFACE], capture_output=True, text=True)
        info(f" Current {VM_IFACE} config:\n{result.stdout.strip()}\n")

        # ── Bridge the physical interface into OVS ──
        info(f"\n[+] Bridging {VM_IFACE} into OVS switch {primary_switch}\n")
        subprocess.run(["ovs-vsctl", "add-port", primary_switch, VM_IFACE], check=False)

        # Move L3 from NIC → OVS device (assign IP first, bring device up)
        subprocess.run(["ip", "addr", "flush", "dev", VM_IFACE], check=False)
        subprocess.run(["ip", "addr", "add", f"{orig_ip}/{orig_prefix}", "dev", primary_switch], check=False)
        subprocess.run(["ip", "link", "set", primary_switch, "up"], check=False)

        # SAFER: atomically replace default route only if we know a gateway
        if orig_gw:
            subprocess.run(["ip", "route", "replace", "default", "via", orig_gw, "dev", primary_switch], check=False)
        else:
            info("[!] Skipping default route setup (no gateway detected).\n")

        # Enable IP forwarding and relax FORWARD policy (save/restore iptables)
        iptables_save_path = save_iptables_state()
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-F", "FORWARD"], check=False)

        info(f"[+] Bridge setup complete. VM reachable at {orig_ip} via {primary_switch}\n")

        # ── Assign profiles and start services ──
        info("\n[+] Configuring host fingerprints and services\n")
        for i, (profile_name, profile) in enumerate(profiles):
            host = net.get(f"h{i + 1}")
            ip = host.IP()
            info(f"\n Host h{i+1} ({ip}) → {profile['os_label']}\n")
            apply_os_fingerprint(host, profile)
            pids = start_services(host, profile, tmp_dir)
            host_map[host.name] = {
                "ip": ip,
                "profile": profile_name,
                "label": profile["os_label"],
                "ports": [s[0] for s in profile["services"]],
                "pids": pids,
            }
            time.sleep(0.2)  # let listeners bind

        # ── Verify internal connectivity ──
        info("\n[+] Verifying internal connectivity...\n")
        for i, (profile_name, profile) in enumerate(profiles):
            host = net.get(f"h{i + 1}")
            target_idx = (i + 1) % n_hosts + 1
            result = host.cmd(f"ping -c 1 -W 1 10.0.0.{target_idx}")
            if "1 received" in result:
                info(f" ✓ {host.name} → 10.0.0.{target_idx} OK\n")
            else:
                info(f" ✗ {host.name} → 10.0.0.{target_idx} FAILED\n")

        # Print summary table
        print("\n" + "=" * 65)
        print(f"{'Host':<6} {'IP':<14} {'OS Fingerprint':<25} {'Ports'}")
        print("=" * 65)
        for name, info_d in host_map.items():
            ports = ", ".join(str(p) for p in info_d["ports"])
            print(f"{name:<6} {info_d['ip']:<14} {info_d['label']:<25} {ports}")
        print("=" * 65)

        # Print Nmap commands
        subnet = "10.0.0.0/24"
        print(f"""
Scan from your Windows host:
  # Quick ping sweep:
  nmap -sn {subnet}
  # OS fingerprint + service version scan:
  nmap -O -sV -T4 {subnet}
  # Aggressive scan (all ports):
  nmap -A -T4 {subnet}

Scan from inside Mininet CLI:
  mininet> h1 nmap -O -sV {subnet}

Open Mininet CLI → type 'exit' or Ctrl-D to stop the network.
""")

        CLI(net)

    finally:
        # ── Cleanup ──
        info("\n[+] Stopping network...\n")

        # Stop service listeners
        for name, info_d in host_map.items():
            host = net.get(name)
            for pid in info_d["pids"]:
                host.cmd(f"kill {pid} 2>/dev/null")

        # Move L3 back: OVS → NIC (and restore default route atomically)
        if primary_switch and VM_IFACE and orig_ip and orig_prefix:
            subprocess.run(["ovs-vsctl", "del-port", primary_switch, VM_IFACE], check=False)
            subprocess.run(["ip", "addr", "flush", "dev", VM_IFACE], check=False)
            subprocess.run(["ip", "addr", "add", f"{orig_ip}/{orig_prefix}", "dev", VM_IFACE], check=False)
            subprocess.run(["ip", "link", "set", VM_IFACE, "up"], check=False)
            if orig_gw:
                subprocess.run(["ip", "route", "replace", "default", "via", orig_gw, "dev", VM_IFACE], check=False)
            else:
                info("[!] No recorded original gateway; leaving default route unchanged.\n")

        # Restore iptables rules
        if iptables_save_path:
            restore_iptables_state(iptables_save_path)
            try:
                os.remove(iptables_save_path)
            except Exception:
                pass

        # Remove temp dir with service scripts
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        # Stop Mininet and clean OVS namespaces
        try:
            net.stop()
        except Exception:
            pass
        subprocess.run(["mn", "--clean"], capture_output=True)

        print("[+] Network stopped and cleaned up.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mininet virtual network with OS fingerprint spoofing"
    )
    parser.add_argument(
        "--topo",
        choices=["star", "linear", "tree"],
        default="star",
        help="Network topology (default: star)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose Mininet logging"
    )
    args = parser.parse_args()
    build_network(topo_name=args.topo, verbose=args.verbose)