import subprocess
import logging
import re
import socket
import struct
import requests

logger = logging.getLogger(__name__)

BITAXE_INDICATORS = ["bitaxeVersion", "hostname", "asicCount", "asicModel"]


def normalize_mac(mac):
    return mac.lower().replace("-", ":").strip()


def get_arp_table():
    entries = {}
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3]
                hw_type = parts[2]
                if mac != "00:00:00:00:00:00" and hw_type == "0x1":
                    entries[normalize_mac(mac)] = ip
        if entries:
            logger.info(f"Parsed {len(entries)} entries from /proc/net/arp")
            return entries
    except FileNotFoundError:
        logger.debug("/proc/net/arp not available, trying fallback")
    except Exception as e:
        logger.warning(f"Error parsing /proc/net/arp: {e}")

    return _parse_arp_command()


def _parse_arp_command():
    entries = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\).*?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
            if match:
                ip = match.group(1)
                mac = normalize_mac(match.group(2))
                entries[mac] = ip
        if entries:
            logger.info(f"Parsed {len(entries)} entries from arp -a")
    except Exception as e:
        logger.warning(f"Error running arp -a: {e}")
    return entries


def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "192.168.1.1"

    try:
        result = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            if local_ip in line:
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if match:
                    ip = match.group(1)
                    prefix = int(match.group(2))
                    packed_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
                    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                    network = packed_ip & mask
                    return f"{socket.inet_ntoa(struct.pack('!I', network))}/{prefix}", ip
    except Exception:
        pass

    return "192.168.1.0/24", local_ip


def ping_sweep(subnet_cidr):
    network, prefix_str = subnet_cidr.split("/")
    prefix = int(prefix_str)
    num_hosts = 2 ** (32 - prefix)
    if num_hosts > 256:
        logger.warning(f"Subnet {subnet_cidr} has {num_hosts} hosts, limiting to 256")
        num_hosts = 256

    packed_net = struct.unpack("!I", socket.inet_aton(network))[0]
    ips = []
    for i in range(1, min(num_hosts, 256)):
        ip = socket.inet_ntoa(struct.pack("!I", packed_net | i))
        ips.append(ip)

    logger.info(f"Pinging {len(ips)} hosts in {subnet_cidr}")
    procs = []
    for ip in ips:
        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                timeout=3
            )
        except Exception:
            pass

    logger.info("Ping sweep complete, ARP table should be populated")


def verify_bitaxe(ip, timeout=5):
    try:
        resp = requests.get(f"http://{ip}/api/system/info", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if any(k in data for k in BITAXE_INDICATORS):
            return data
    except Exception as e:
        logger.debug(f"{ip} is not a Bitaxe: {e}")
    return None


def discover_by_macs(mac_list):
    target_macs = {normalize_mac(m) for m in mac_list if m.strip()}
    if not target_macs:
        return {"error": "No valid MAC addresses provided"}

    logger.info(f"Scanning for MACs: {target_macs}")

    subnet, local_ip = get_local_subnet()
    logger.info(f"Local subnet: {subnet}, local IP: {local_ip}")

    ping_sweep(subnet)

    arp_table = get_arp_table()

    results = []
    for mac, ip in arp_table.items():
        if mac in target_macs:
            logger.info(f"Found MAC {mac} at IP {ip}, verifying Bitaxe...")
            info = verify_bitaxe(ip)
            if info:
                results.append({
                    "mac": mac,
                    "ip": ip,
                    "info": info,
                    "hostname": info.get("hostname", ip),
                    "version": info.get("bitaxeVersion", "unknown")
                })
                logger.info(f"Confirmed Bitaxe at {ip}: {info.get('hostname', '')} v{info.get('bitaxeVersion', '')}")
            else:
                results.append({
                    "mac": mac,
                    "ip": ip,
                    "info": None,
                    "hostname": None,
                    "version": None,
                    "error": "Not a Bitaxe device"
                })
                logger.warning(f"Device at {ip} with MAC {mac} is not a Bitaxe")

    for mac in target_macs:
        if not any(r["mac"] == mac for r in results):
            results.append({
                "mac": mac,
                "ip": None,
                "info": None,
                "hostname": None,
                "version": None,
                "error": "Not found on network"
            })

    return {"results": results, "subnet": subnet}
