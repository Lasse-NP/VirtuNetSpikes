#!/usr/bin/env python3
"""
Mininet Virtual Network with OS Fingerprint Spoofing
Builds a virtual network of hosts with different OS fingerprints, scannable by Nmap.
Automated for external scanning with a 10.0.0.100 gateway.

Usage:
    sudo python3 network.py [--topo star|linear|tree] [--verbose]
"""

import argparse
import sys
import os
import time
import subprocess
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.topo import Topo

# ── OS Fingerprint profiles ────────────────────────────────────────────────────
OS_PROFILES = {
    "windows_server_2019": {
        "ttl": 128,
        "tcp_window": 65535,
        "os_label": "Windows Server 2019",
        "services": [
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135,  "raw",   ""),
            (139,  "raw",   ""),
            (445,  "raw",   ""),
            (3389, "raw",   ""),
        ],
    },
    "ubuntu_22": {
        "ttl": 64,
        "tcp_window": 29200,
        "os_label": "Ubuntu 22.04 LTS",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"),
            (3306, "raw",   ""),
        ],
    },
    "centos_7": {
        "ttl": 64,
        "tcp_window": 14600,
        "os_label": "CentOS 7",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_7.4\r\n"),
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (CentOS)\r\nContent-Length: 0\r\n\r\n"),
            (443,  "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (CentOS)\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "cisco_ios": {
        "ttl": 255,
        "tcp_window": 4128,
        "os_label": "Cisco IOS 15.x",
        "services": [
            (23,   "raw",   "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"),
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: cisco-IOS\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "freebsd_13": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "FreeBSD 13",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_9.0 FreeBSD-20221006\r\n"),
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (FreeBSD)\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "android_device": {
        "ttl": 64,
        "tcp_window": 65700,
        "os_label": "Android 12",
        "services": [
            (5555, "raw",   "CNXN\x00\x00\x00\x01"),
            (8080, "http",  "HTTP/1.1 200 OK\r\nServer: BaseHTTP/0.6 Python/3.10\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "macos_ventura": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "macOS Ventura 13",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_9.0\r\n"),
            (548,  "raw",   ""),
            (5900, "raw",   "RFB 003.889\n"),
        ],
    },
    "windows_10": {
        "ttl": 128,
        "tcp_window": 64240,
        "os_label": "Windows 10",
        "services": [
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135,  "raw",   ""),
            (445,  "raw",   ""),
        ],
    },
}

# ── Topology definitions ───────────────────────────────────────────────────────

class StarTopo(Topo):
    def build(self, n_hosts=8):
        switch = self.addSwitch("s1")
        for i in range(1, n_hosts + 1):
            host = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(host, switch)

class LinearTopo(Topo):
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
port   = {port}

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
signal.signal(signal.SIGINT,  stopper)

while True:
    try:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except OSError:
        break
"""

def apply_os_fingerprint(host, profile):
    ttl    = profile["ttl"]
    window = profile["tcp_window"]
    label  = profile["os_label"]
    info(f"  [*] {host.name}: applying fingerprint → {label}\n")
    host.cmd(f"sysctl -w net.ipv4.ip_default_ttl={ttl}")
    host.cmd(f"sysctl -w net.ipv4.tcp_rmem='4096 {window} {window * 4}'")
    host.cmd(f"sysctl -w net.core.rmem_default={window}")
    host.cmd(f"sysctl -w net.core.rmem_max={window * 4}")
    if ttl == 128:
        host.cmd("sysctl -w net.ipv4.tcp_timestamps=0")
        host.cmd("sysctl -w net.ipv4.tcp_sack=1")
    else:
        host.cmd("sysctl -w net.ipv4.tcp_timestamps=1")
    host.cmd("sysctl -w net.ipv4.icmp_echo_ignore_all=0")

def start_services(host, profile, tmp_dir):
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
            info(f"    → {host.name}:{port}/{proto} (pid {pid})\n")
    return pids

# ── Main ───────────────────────────────────────────────────────────────────────

def build_network(topo_name="star", verbose=False):
    if os.geteuid() != 0:
        error("ERROR: This script must be run as root (sudo).\n")
        sys.exit(1)

    setLogLevel("info" if verbose else "warning")
    profiles = list(OS_PROFILES.items())
    n_hosts  = len(profiles)

    info(f"\n[+] Building '{topo_name}' topology with {n_hosts} hosts\n")

    if topo_name == "star":
        topo = StarTopo(n_hosts=n_hosts)
    elif topo_name == "linear":
        topo = LinearTopo(n_hosts=n_hosts)
    else:
        topo = TreeTopo(n_hosts=n_hosts)

    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,
        autoSetMacs=True,
    )
    net.start()

    # Configure switches to standalone mode
    for switch in net.switches:
        info(f"[+] Setting {switch.name} to standalone mode\n")
        subprocess.run(["ovs-vsctl", "del-controller", switch.name], check=False)
        subprocess.run(["ovs-vsctl", "set-fail-mode", switch.name, "standalone"], check=False)
        subprocess.run(["ovs-ofctl", "del-flows", switch.name], check=False)
        subprocess.run(["ovs-ofctl", "add-flow", switch.name, "priority=0,actions=NORMAL"], check=False)

    # Bridge the physical interface and set Gateway IP
    VM_IFACE = "enp0s3"
    info(f"\n[+] Bridging {VM_IFACE} and setting gateway 10.0.0.100\n")
    
    # Assign the Gateway IP to the switch bridge
    subprocess.run(["ip", "addr", "add", "10.0.0.100/24", "dev", "s1"], check=False)
    
    # Bridge physical NIC
    subprocess.run(["ovs-vsctl", "add-port", "s1", VM_IFACE], check=False)
    subprocess.run(["ip", "addr", "flush", "dev", VM_IFACE], check=False)
    subprocess.run(["ip", "addr", "add", "192.168.0.27/24", "dev", "s1"], check=False)
    subprocess.run(["ip", "link", "set", "s1", "up"], check=False)
    
    # Fix Routing
    subprocess.run(["ip", "route", "del", "default"], capture_output=True, check=False)
    subprocess.run(["ip", "route", "add", "default", "via", "192.168.0.1", "dev", "s1"], check=False)
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

    tmp_dir = "/tmp/mininet_services"
    os.makedirs(tmp_dir, exist_ok=True)

    info("\n[+] Configuring host fingerprints, services, and gateways\n")
    host_map = {}
    for i, (profile_name, profile) in enumerate(profiles):
        host = net.get(f"h{i + 1}")
        ip   = host.IP()
        
        # Apply Fingerprint and Start Services
        apply_os_fingerprint(host, profile)
        pids = start_services(host, profile, tmp_dir)
        
        # Set Default Gateway on each host
        host.cmd("ip route add default via 10.0.0.100")
        
        host_map[host.name] = {
            "ip":      ip,
            "label":   profile["os_label"],
            "ports":   [s[0] for s in profile["services"]],
            "pids":    pids,
        }

    print("\n" + "=" * 65)
    print(f"{'Host':<6} {'IP':<14} {'OS Fingerprint':<25} {'Ports'}")
    print("=" * 65)
    for name, info_d in host_map.items():
        ports = ", ".join(str(p) for p in info_d["ports"])
        print(f"{name:<6} {info_d['ip']:<14} {info_d['label']:<25} {ports}")
    print("=" * 65)

    CLI(net)

    # Cleanup
    info("\n[+] Cleaning up...\n")
    for name, info_d in host_map.items():
        host = net.get(name)
        for pid in info_d["pids"]:
            host.cmd(f"kill {pid} 2>/dev/null")

    subprocess.run(["ovs-vsctl", "del-port", "s1", VM_IFACE], check=False)
    subprocess.run(["ip", "addr", "add", "192.168.0.27/24", "dev", VM_IFACE], check=False)
    subprocess.run(["ip", "link", "set", VM_IFACE, "up"], check=False)
    subprocess.run(["ip", "route", "add", "default", "via", "192.168.0.1", "dev", VM_IFACE], check=False)
    net.stop()
    subprocess.run(["mn", "--clean"], capture_output=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--topo", choices=["star", "linear", "tree"], default="star")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    build_network(topo_name=args.topo, verbose=args.verbose)