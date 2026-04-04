import subprocess
import logging
import re
import socket
import struct
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

BITAXE_INDICATORS = ["bitaxeVersion", "hostname", "asicCount", "asicModel"]

def normalize_mac(mac):
    if not mac:
        return None
    return mac.lower().replace("-", ":").strip()


def parse_subnet_from_endpoints(endpoints):
    """Extract subnet from configured endpoints. E.g. ['http://192.168.0.11'] -> '192.168.0.0/24'"""
    if not endpoints:
        return "192.168.1.0/24"
    
    ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.)(\d+)')
    for ep in endpoints:
        match = ip_pattern.search(ep)
        if match:
            base = match.group(1)
            return f"{base}0/24"
    
    return "192.168.1.0/24"


def ping_host(ip, timeout=1):
    """Check if a host is reachable via ping. Returns True if host responds."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_subnet(subnet_cidr):
    """Ping sweep the given subnet and return list of live IPs."""
    network, prefix_str = subnet_cidr.split("/")
    prefix = int(prefix_str)
    num_hosts = 2 ** (32 - prefix)
    if num_hosts > 256:
        num_hosts = 256

    packed_net = struct.unpack("!I", socket.inet_aton(network))[0]
    ips = []
    for i in range(1, min(num_hosts, 256)):
        ip = socket.inet_ntoa(struct.pack("!I", packed_net | i))
        ips.append(ip)

    logger.info(f"Ping sweeping {len(ips)} hosts in {subnet_cidr}")

    live_ips = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            if future.result():
                live_ips.append(futures[future])

    logger.info(f"Found {len(live_ips)} live hosts: {live_ips}")
    return live_ips


def verify_bitaxe(ip, timeout=5):
    """Check if an IP is a Bitaxe by querying /api/system/info."""
    try:
        resp = requests.get(f"http://{ip}/api/system/info", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if any(k in data for k in BITAXE_INDICATORS):
            return data
    except Exception as e:
        logger.debug(f"{ip} is not a Bitaxe: {e}")
    return None


def scan_bitaxes(live_ips):
    """Given a list of live IPs, probe each for Bitaxe info. Returns dict keyed by IP."""
    results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(verify_bitaxe, ip): ip for ip in live_ips}
        for future in as_completed(futures):
            ip = futures[future]
            info = future.result()
            if info:
                results[ip] = info
                logger.info(f"Found Bitaxe at {ip}: {info.get('hostname', '')} v{info.get('bitaxeVersion', '')}")
    return results


def discover_by_macs(mac_list, subnet=None, endpoints=None):
    """Scan the given subnet for Bitaxes matching the provided MAC addresses.
    
    Args:
        mac_list: List of MAC addresses to search for
        subnet: Subnet to scan (e.g. '192.168.0.0/24'). Auto-detected if not provided.
        endpoints: List of configured endpoints. Used to derive subnet if not explicitly provided.
    
    Returns:
        Dict with 'results' list and 'subnet' scanned.
    """
    logger.info(f"=== DISCOVER BY MACS START ===")
    logger.info(f"mac_list={mac_list}, subnet={subnet}, endpoints={endpoints}")
    
    target_macs = {normalize_mac(m) for m in mac_list if m.strip()}
    if not target_macs:
        logger.warning("No valid MAC addresses provided")
        return {"error": "No valid MAC addresses provided"}

    if not subnet:
        subnet = parse_subnet_from_endpoints(endpoints or [])
    if isinstance(subnet, list):
        subnet = parse_subnet_from_endpoints(subnet)

    logger.info(f"Target MACs: {target_macs}")
    logger.info(f"Scanning subnet {subnet}")

    logger.info("Step 1: Ping sweeping subnet...")
    live_ips = scan_subnet(subnet)
    logger.info(f"Step 1 complete: {len(live_ips)} live hosts: {live_ips}")

    logger.info("Step 2: Probing live hosts for Bitaxe info...")
    bitaxes = scan_bitaxes(live_ips)
    logger.info(f"Step 2 complete: {len(bitaxes)} Bitaxes found: {list(bitaxes.keys())}")

    results = []
    for ip, info in bitaxes.items():
        mac = normalize_mac(info.get("macAddr", ""))
        logger.info(f"Checking IP {ip}: mac={mac}, target_macs={target_macs}")
        if mac in target_macs:
            logger.info(f"  ==> MATCH! Found target MAC {mac} at IP {ip}")
            results.append({
                "mac": mac,
                "ip": ip,
                "info": info,
                "hostname": info.get("hostname", ip),
                "version": info.get("bitaxeVersion", "unknown")
            })
        else:
            logger.info(f"  ==> No match: {mac} not in target MACs")

    for mac in target_macs:
        if not any(r["mac"] == mac for r in results):
            logger.info(f"MAC {mac} not found on network")
            results.append({
                "mac": mac,
                "ip": None,
                "info": None,
                "hostname": None,
                "version": None,
                "error": "Not found on network"
            })

    logger.info(f"=== DISCOVER BY MACS END: {len(results)} results ===")
    return {"results": results, "subnet": subnet}
