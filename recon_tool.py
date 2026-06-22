#!/usr/bin/env python3
"""
linux_system_recon_tool.py

A hardened, professional-grade Linux system and network reconnaissance tool.
Gathers host information, enumerates network interfaces, discovers LAN devices,
and exports a structured JSON report. Built for cybersecurity education and
authorized security assessments.

Author  : Aditya Gupta
GitHub  : https://github.com/adityainfosec
License : MIT
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------

PROGRAM_NAME = "Linux System Network Recon Tool"
PROGRAM_VERSION = "2.0.0"
REPORT_FILENAME = "recon_report.json"
DEFAULT_TIMEOUT = 5  # seconds for subprocess calls
LOGGING_FORMAT = "[%(levelname)s] %(message)s"

# Colour codes for terminal output (ANSI)
COLOUR_GREEN = "\033[92m"
COLOUR_YELLOW = "\033[93m"
COLOUR_CYAN = "\033[96m"
COLOUR_RED = "\033[91m"
COLOUR_RESET = "\033[0m"
COLOUR_BOLD = "\033[1m"

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Utility Helpers
# ---------------------------------------------------------------------------

def colourise(text: str, colour: str) -> str:
    """Wrap *text* in an ANSI colour code for terminal highlighting."""
    return f"{colour}{text}{COLOUR_RESET}"


def bold(text: str) -> str:
    """Return *text* wrapped in ANSI bold escape codes."""
    return f"{COLOUR_BOLD}{text}{COLOUR_RESET}"


def success(msg: str) -> None:
    """Print a success message (green)."""
    print(colourise(f"[✔] {msg}", COLOUR_GREEN))


def warning(msg: str) -> None:
    """Print a warning message (yellow)."""
    print(colourise(f"[!] {msg}", COLOUR_YELLOW))


def info(msg: str) -> None:
    """Print an informational message (cyan)."""
    print(colourise(f"[i] {msg}", COLOUR_CYAN))


def error(msg: str) -> None:
    """Print an error message (red)."""
    print(colourise(f"[✘] {msg}", COLOUR_RED), file=sys.stderr)


def run_subprocess(cmd: List[str], timeout: int = DEFAULT_TIMEOUT) -> Tuple[str, str, int]:
    """
    Execute a system command safely with a timeout.

    Args:
        cmd:     Command and arguments as a list (e.g. ``["ip", "a"]``).
        timeout: Seconds before the process is killed.

    Returns:
        ``(stdout, stderr, returncode)``

    Raises:
        RuntimeError: If the command is not found on the system.
    """
    if not shutil.which(cmd[0]):
        raise RuntimeError(f"Required binary not found: {cmd[0]}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
        return "", f"TIMEOUT after {timeout}s", -1
    except OSError as exc:
        raise RuntimeError(f"Failed to execute {' '.join(cmd)}: {exc}") from exc


def validate_mac_address(mac: str) -> bool:
    """Return ``True`` if *mac* is a valid IEEE 802 MAC address (colon-separated)."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac))


def validate_ip_address(ip: str) -> bool:
    """Return ``True`` if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# System Information Collector
# ---------------------------------------------------------------------------

def get_hostname() -> str:
    """Retrieve the system hostname via :func:`socket.gethostname`."""
    try:
        return socket.gethostname()
    except OSError as exc:
        logger.error("Failed to resolve hostname: %s", exc)
        return "UNKNOWN"


def get_local_ip() -> str:
    """
    Determine the primary local IP address by connecting to a public resolver.

    Falls back to ``127.0.0.1`` if the external connection fails.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            # Connects to Google DNS — no real data is sent.
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except (socket.error, OSError) as exc:
        logger.warning("Could not determine local IP via external socket: %s", exc)
        return "127.0.0.1"


def get_mac_address() -> str:
    """
    Return the MAC address of the primary interface using :func:`uuid.getnode`.

    Returns ``"00:00:00:00:00:00"`` on failure.
    """
    node = uuid.getnode()
    if (node >> 40) == 0:  # unlikely — indicates failure
        logger.warning("uuid.getnode() returned 0 or invalid value")
        return "00:00:00:00:00:00"
    mac = ":".join(f"{(node >> (8 * i)) & 0xFF:02x}" for i in range(5, -1, -1))
    return mac


def get_os_info() -> Dict[str, str]:
    """
    Gather operating-system-level information.

    Returns:
        A dict with keys ``system``, ``kernel``, ``architecture``,
        and (on Linux) ``distro``.
    """
    info: Dict[str, str] = {
        "system": platform.system(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
    }
    # Try to get a more specific distribution name on Linux
    try:
        import platform
        # Python 3.10+ has freedesktop_os_release; fallback otherwise.
        if hasattr(platform, "freedesktop_os_release"):
            osrel = platform.freedesktop_os_release()
            info["distro"] = osrel.get("PRETTY_NAME", osrel.get("NAME", "Unknown"))
        else:
            # Try reading /etc/os-release manually
            osrel_path = Path("/etc/os-release")
            if osrel_path.exists():
                with open(osrel_path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.startswith("PRETTY_NAME="):
                            info["distro"] = line.strip().split("=", 1)[1].strip('"')
                            break
    except (ImportError, OSError, IOError):
        pass
    return info


# ---------------------------------------------------------------------------
# Network Interface Enumerator
# ---------------------------------------------------------------------------

def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerate all active (UP) network interfaces with IP and MAC details.

    Uses ``ip -json a`` (preferred) with a fallback to parsing ``ip a``.

    Returns:
        A list of dicts, each containing ``name``, ``ipv4``, ``ipv6``, ``mac``,
        and ``state``.  Empty list if enumeration fails.
    """
    interfaces: List[Dict[str, Any]] = []

    # --- Attempt JSON mode (ip -json a) ---
    try:
        stdout, _, rc = run_subprocess(["ip", "-json", "a"])
        if rc == 0 and stdout:
            raw = json.loads(stdout)
            for iface in raw:
                name = iface.get("ifname", "?")
                state = iface.get("operstate", "UNKNOWN")
                mac_addr = (iface.get("address", "") or "").lower()
                ipv4_list: List[str] = []
                ipv6_list: List[str] = []
                for addr_info in iface.get("addr_info", []):
                    ip = addr_info.get("local", "")
                    family = addr_info.get("family", "")
                    if family == "inet":
                        ipv4_list.append(ip)
                    elif family == "inet6":
                        ipv6_list.append(ip)
                interfaces.append({
                    "name": name,
                    "state": state,
                    "mac": mac_addr if validate_mac_address(mac_addr) else "",
                    "ipv4": ipv4_list,
                    "ipv6": ipv6_list,
                })
            return interfaces
    except (json.JSONDecodeError, RuntimeError, OSError) as exc:
        logger.debug("ip -json a failed, falling back to text parsing: %s", exc)

    # --- Fallback: text parsing of ip a ---
    try:
        stdout, _, rc = run_subprocess(["ip", "a"])
        if rc != 0 or not stdout:
            return interfaces
    except RuntimeError as exc:
        logger.error("Could not enumerate network interfaces: %s", exc)
        return interfaces

    current_iface: Optional[Dict[str, Any]] = None
    for line in stdout.splitlines():
        # Match interface header — e.g. "2: eth0: ..."
        header_match = re.match(r"^\d+:\s+(\S+):\s+.*state\s+(\S+)", line)
        if header_match:
            if current_iface:
                interfaces.append(current_iface)
            current_iface = {
                "name": header_match.group(1),
                "state": header_match.group(2),
                "mac": "",
                "ipv4": [],
                "ipv6": [],
            }
            # Try to grab MAC from the same line (link/ether ...)
            mac_m = re.search(r"link/ether\s+([0-9a-f:]+)", line.lower())
            if mac_m:
                candidate = mac_m.group(1)
                if validate_mac_address(candidate):
                    current_iface["mac"] = candidate
            continue

        if current_iface is None:
            continue

        # MAC on subsequent line
        mac_m = re.search(r"link/ether\s+([0-9a-f:]+)", line.lower())
        if mac_m:
            candidate = mac_m.group(1)
            if validate_mac_address(candidate):
                current_iface["mac"] = candidate

        # IPv4 address
        ipv4_m = re.search(r"inet\s+(\S+)", line)
        if ipv4_m:
            ip_candidate = ipv4_m.group(1).split("/")[0]
            if validate_ip_address(ip_candidate):
                current_iface["ipv4"].append(ip_candidate)

        # IPv6 address (global / link-local)
        ipv6_m = re.search(r"inet6\s+(\S+)", line)
        if ipv6_m:
            ip_candidate = ipv6_m.group(1).split("/")[0]
            if validate_ip_address(ip_candidate):
                current_iface["ipv6"].append(ip_candidate)

    if current_iface:
        interfaces.append(current_iface)

    return interfaces


# ---------------------------------------------------------------------------
# LAN Device Discovery
# ---------------------------------------------------------------------------

def discover_lan_devices() -> List[Dict[str, str]]:
    """
    Discover active LAN neighbours by parsing the kernel ARP cache (``ip neigh``).

    Returns:
        A list of dicts with keys ``ip``, ``mac``, ``state``, and ``interface``.
    """
    devices: List[Dict[str, str]] = []
    try:
        stdout, _, rc = run_subprocess(["ip", "neigh"])
        if rc != 0 or not stdout:
            warning("ARP cache is empty or inaccessible — no LAN neighbours found.")
            return devices
    except RuntimeError as exc:
        error(f"LAN device discovery failed: {exc}")
        return devices

    for line in stdout.splitlines():
        parts = re.split(r"\s+", line.strip())
        # Typical format:
        # 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        if len(parts) < 5:
            continue
        ip_candidate = parts[0]
        if not validate_ip_address(ip_candidate):
            continue
        mac_addr = ""
        state = "UNKNOWN"
        iface = ""
        # Find lladdr field and state
        for idx, token in enumerate(parts):
            if token == "lladdr" and (idx + 1) < len(parts):
                candidate = parts[idx + 1].lower()
                if validate_mac_address(candidate):
                    mac_addr = candidate
            if token == "dev" and (idx + 1) < len(parts):
                iface = parts[idx + 1]
            # Remaining tokens after lladdr usually contain state
        # The state is typically the last token
        # Remove ip, dev, iface, lladdr, mac — what's left is state
        known_tokens = {parts[0], "dev", iface, "lladdr", mac_addr}
        remaining = [p for p in parts if p not in known_tokens and p != ""]
        if remaining:
            state = remaining[-1]
        else:
            state = "UNKNOWN"

        devices.append({
            "ip": ip_candidate,
            "mac": mac_addr,
            "state": state,
            "interface": iface,
        })

    return devices


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_report(
    hostname: str,
    local_ip: str,
    mac: str,
    os_info: Dict[str, str],
    interfaces: List[Dict[str, Any]],
    devices: List[Dict[str, str]],
) -> Dict[str, Any]:
    """
    Assemble a nested dictionary representing the full reconnaissance report.

    Args:
        hostname:   System hostname.
        local_ip:   Primary local IP address.
        mac:        Primary MAC address.
        os_info:    Operating-system information dict.
        interfaces: List of network interfaces.
        devices:    List of discovered LAN devices.

    Returns:
        A JSON-serialisable report dictionary.
    """
    return {
        "tool": PROGRAM_NAME,
        "version": PROGRAM_VERSION,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": {
            "hostname": hostname,
            "local_ip": local_ip,
            "mac_address": mac,
            "os": os_info,
        },
        "network_interfaces": interfaces,
        "lan_devices": devices,
    }


def save_report(report: Dict[str, Any], filepath: str = REPORT_FILENAME) -> None:
    """
    Write the reconnaissance report to a JSON file on disk.

    Args:
        report:   Report dictionary.
        filepath: Destination file path.

    Raises:
        IOError: If the file cannot be written.
    """
    try:
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=4, default=str)
        success(f"Report saved → {filepath}")
    except (IOError, OSError) as exc:
        raise IOError(f"Failed to write report to {filepath}: {exc}") from exc


# ---------------------------------------------------------------------------
# Display / Pretty-Print
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Print the tool banner to stdout."""
    banner_width = 60
    print()
    print(colourise("=" * banner_width, COLOUR_CYAN))
    print(colourise(f"  {PROGRAM_NAME} v{PROGRAM_VERSION}", COLOUR_BOLD + COLOUR_CYAN))
    print(colourise("  Author: Aditya Gupta  |  github.com/adityainfosec", COLOUR_CYAN))
    print(colourise("=" * banner_width, COLOUR_CYAN))
    print()


def print_system_info(hostname: str, local_ip: str, mac: str, os_info: Dict[str, str]) -> None:
    """Pretty-print the system-information section."""
    print(bold("── System Information ──"))
    print(f"  {bold('Hostname')}        : {hostname}")
    print(f"  {bold('Local IP')}         : {local_ip}")
    print(f"  {bold('MAC Address')}      : {mac}")
    print(f"  {bold('Operating System')} : {os_info.get('system', '?')} "
          f"({os_info.get('distro', 'N/A')})")
    print(f"  {bold('Kernel')}           : {os_info.get('kernel', '?')}")
    print(f"  {bold('Architecture')}     : {os_info.get('architecture', '?')}")
    print()


def print_interfaces(interfaces: List[Dict[str, Any]]) -> None:
    """Pretty-print the network-interfaces section."""
    print(bold("── Network Interfaces ──"))
    if not interfaces:
        warning("No network interfaces discovered.")
        print()
        return

    header = f"  {'Interface':<12} {'State':<10} {'MAC Address':<20} {'IPv4':<20} {'IPv6'}"
    print(header)
    print("  " + "-" * len(header))
    for iface in interfaces:
        name = iface.get("name", "?")
        state = iface.get("state", "?")
        mac = iface.get("mac", "")
        ipv4 = ", ".join(iface.get("ipv4", [])) or "—"
        ipv6 = ", ".join(iface.get("ipv6", [])) or "—"
        print(f"  {name:<12} {state:<10} {mac:<20} {ipv4:<20} {ipv6}")
    print()


def print_lan_devices(devices: List[Dict[str, str]]) -> None:
    """Pretty-print the LAN device-discovery section."""
    print(bold("── LAN Devices ──"))
    if not devices:
        warning("No LAN devices discovered from ARP cache.")
        print()
        return

    header = f"  {'IP Address':<20} {'MAC Address':<20} {'State':<12} {'Interface'}"
    print(header)
    print("  " + "-" * len(header))
    for d in devices:
        print(f"  {d['ip']:<20} {d['mac']:<20} {d['state']:<12} {d.get('interface', '?')}")
    print()


# ---------------------------------------------------------------------------
# Command-Line Argument Parsing
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse and return command-line arguments.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        An ``argparse.Namespace`` with attributes:
        ``--output``, ``--verbose``, ``--version``.
    """
    parser = argparse.ArgumentParser(
        prog="linux-system-recon-tool",
        description=f"{PROGRAM_NAME} — Gather Linux system & network intelligence.",
        epilog="For authorised security assessments only.",
    )
    parser.add_argument(
        "-o", "--output",
        default=REPORT_FILENAME,
        help=f"Output JSON report path (default: {REPORT_FILENAME})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROGRAM_NAME} v{PROGRAM_VERSION}",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """
    Orchestrate the full reconnaissance workflow.

    Args:
        argv: Optional argument list (for testing / embedding).

    Returns:
        Exit code: ``0`` on success, ``1`` on failure.
    """
    args = parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    print_banner()

    # ------------------------------------------------------------------
    # 1. System Information
    # ------------------------------------------------------------------
    info("Collecting system information …")
    hostname = get_hostname()
    local_ip = get_local_ip()
    mac = get_mac_address()
    os_info = get_os_info()
    print_system_info(hostname, local_ip, mac, os_info)

    # ------------------------------------------------------------------
    # 2. Network Interfaces
    # ------------------------------------------------------------------
    info("Enumerating network interfaces …")
    interfaces = get_network_interfaces()
    print_interfaces(interfaces)
    # ---------------------------------------------------------------------------
# 3. LAN Device Discovery
# ---------------------------------------------------------------------------

info("Scanning ARP cache for LAN neighbours ...")
devices = discover_lan_devices()
print_lan_devices(devices)

# ---------------------------------------------------------------------------
# 4. Generate & Save Report
# ---------------------------------------------------------------------------

info("Assembling reconnaissance report ...")
report = generate_report(hostname, local_ip, mac, os_info, interfaces, devices)

try:
    save_report(report, args.output)
except IOError as exc:
    error(str(exc))
    return 1

print(colourise("=" * 60, COLOUR_CYAN))
success(
    f"Reconnaissance complete — {len(interfaces)} interface(s), "
    f"{len(devices)} LAN device(s)."
)
print()

return 0


# ---------------------------------------------------------------------------
# Entry Guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        warning("Interrupted by user.")
        sys.exit(130)
    except RuntimeError as exc:
        error(f"Fatal runtime error: {exc}")
        sys.exit(1)
