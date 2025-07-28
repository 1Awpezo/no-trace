import subprocess
import time
import logging
from logging.handlers import RotatingFileHandler
import sys
import os
import random
import shutil
import platform
import getpass
import json
import ctypes
import psutil
import requests
import re
import threading
import argparse
import configparser
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
import hashlib
import socket
import getmac
import urllib.parse
import ipaddress
import xml.etree.ElementTree as ET

# Configuration file path
CONFIG_FILE = "no_trace_config.ini"

# Initialize logging with rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('no_trace.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ASCII Banner
BANNER = """
███╗   ██╗ ██████╗    ████████╗██████╗  █████╗  ██████╗███████╗
████╗  ██║██╔═══██╗   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██╔██╗ ██║██║   ██║█████╗██║   ██████╔╝███████║██║     █████╗  
██║╚██╗██║██║   ██║╚════╝██║   ██╔══██╗██╔══██║██║     ██╔══╝  
██║ ╚████║╚██████╔╝      ██║   ██║  ██║██║  ██║╚██████╗███████╗
╚═╝  ╚═══╝ ╚═════╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
"""

# Default configuration
DEFAULT_CONFIG = {
    'mullvad': {
        'account_number': 'YOUR_ACCOUNT_NUMBER_HERE',
        'rotation_interval': '300',
        'preferred_countries': 'us,ca,uk',
        'connection_timeout': '10'
    },
    'privacy': {
        'browsers_to_clear': 'Edge,Chrome,Opera,Opera GX,Brave,Firefox',
        'clear_temp': 'True',
        'clear_logs': 'True'
    },
    'network': {
        'spoof_mac': 'False',
        'randomize_user_agent': 'True',
        'disable_webrtc': 'True'
    }
}

class ConfigManager:
    """Manage configuration file operations."""
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        
    def load_config(self) -> configparser.ConfigParser:
        """Load or create configuration file."""
        if not os.path.exists(self.config_file):
            self.config.read_dict(DEFAULT_CONFIG)
            with open(self.config_file, 'w') as f:
                self.config.write(f)
        else:
            self.config.read(self.config_file)
        return self.config
    
    def save_config(self, updates: Dict) -> None:
        """Update and save configuration."""
        for section, settings in updates.items():
            if section not in self.config:
                self.config[section] = {}
            self.config[section].update(settings)
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        logger.info("Configuration updated and saved.")

def check_admin_privileges():
    """Check and elevate privileges if needed."""
    if platform.system() == "Windows":
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.info("Elevating to admin privileges...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
    else:
        if os.geteuid() != 0:
            logger.info("Elevating to root with sudo...")
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
            sys.exit(1)

def center_text(text: str) -> str:
    """Center text based on terminal width."""
    terminal_width = shutil.get_terminal_size().columns
    centered_lines = []
    for line in text.splitlines():
        padding = (terminal_width - len(line)) // 2
        centered_lines.append(" " * max(0, padding) + line)
    return "\n".join(centered_lines)

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    """Display the advanced menu with centered banner."""
    clear_screen()
    print(center_text(BANNER))
    print(center_text("Advanced No-Trace Anonymization Tool"))
    print("\nMenu Options:")
    print("1. Mullvad IP Rotator")
    print("2. Advanced MAC Address Spoofer")
    print("3. Clear System Logs and Cache")
    print("4. Disable WebRTC")
    print("5. Randomize User Agent")
    print("6. Log Out All Accounts")
    print("7. Network Privacy Scan")
    print("8. Configure Settings")
    print("9. DNS Leak Protection")
    print("10. System Fingerprint Randomizer")
    print("11. Exit")
    return input("Select an option (1-11): ")

def run_command(command: str, shell: bool = True, powershell: bool = False, timeout: int = 30) -> Optional[str]:
    """Execute a shell or PowerShell command with timeout."""
    try:
        if powershell:
            result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True, check=True, timeout=timeout)
        else:
            result = subprocess.run(command, shell=shell, capture_output=True, text=True, check=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {command}, Error: {e.stderr}")
        return None

def login_mullvad(account_number: str) -> bool:
    """Log in to Mullvad with provided account number."""
    logger.info("Attempting Mullvad login...")
    result = run_command(f"mullvad account login {account_number}")
    if result and "success" in result.lower():
        logger.info("Mullvad login successful.")
        return True
    logger.error("Mullvad login failed.")
    return False

def get_mullvad_servers(preferred_countries: List[str] = None) -> List[str]:
    """Retrieve and filter Mullvad server locations."""
    logger.info("Fetching Mullvad server list...")
    result = run_command("mullvad relay list")
    if not result:
        logger.error("Failed to fetch server list.")
        return []
    
    servers = []
    for line in result.splitlines():
        line = line.strip()
        if line and not line.startswith(" ") and "wireguard" in line.lower():
            country_code = line.split('-')[0]
            if country_code and (not preferred_countries or country_code in preferred_countries):
                servers.append(country_code)
    logger.info(f"Parsed {len(servers)} server locations.")
    return list(set(servers))

def connect_to_server(location: str, timeout: int = 10) -> bool:
    """Connect to a specific Mullvad server location."""
    logger.info(f"Connecting to {location}...")
    result = run_command(f"mullvad relay set location {location}")
    if result:
        run_command("mullvad connect")
        time.sleep(2)
        if check_connection(timeout):
            logger.info(f"Connected to {location}")
            return True
    logger.error(f"Failed to connect to {location}")
    return False

def check_connection(timeout: int = 10) -> bool:
    """Check if VPN connection is active."""
    result = run_command("mullvad status", timeout=timeout)
    return result and "Connected" in result

def disconnect_vpn() -> bool:
    """Disconnect from the current VPN server."""
    logger.info("Disconnecting VPN...")
    run_command("mullvad disconnect")
    time.sleep(2)
    if not check_connection():
        logger.info("VPN disconnected successfully.")
        return True
    logger.error("Failed to disconnect VPN.")
    return False

def spoof_mac_address(interface: str = None, specific_mac: str = None):
    """Spoof MAC address for the specified or primary network interface."""
    logger.info("Attempting to spoof MAC address...")
    if platform.system() == "Windows":
        adapter = run_command(
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*'} | Select-Object -First 1 | Select-Object -ExpandProperty Name",
            powershell=True
        )
        if not adapter:
            logger.error("No active network adapter found.")
            print("Error: No active network adapter found.")
            return False

        mac = specific_mac or ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])
        logger.info(f"Using MAC address: {mac}")

        result = run_command(
            f"Set-NetAdapter -Name '{adapter}' -MacAddress '{mac}'",
            powershell=True
        )
        if result:
            run_command(f"netsh interface set interface '{adapter}' admin=disable")
            time.sleep(1)
            run_command(f"netsh interface set interface '{adapter}' admin=enable")
            logger.info(f"Spoofed MAC address to {mac} on {adapter}")
            print(f"MAC address changed to {mac} on {adapter}.")
            return True
        logger.error("Failed to spoof MAC address.")
        print("Error: Failed to spoof MAC address. Run as Administrator.")
        return False
    else:
        interface = interface or run_command("ip link | grep 'state UP' | awk '{print $2}' | cut -d':' -f1 | head -n1")
        if not interface:
            logger.error("No active network interface found.")
            print("Error: No active network interface found.")
            return False

        mac = specific_mac or ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])
        logger.info(f"Using MAC address: {mac}")

        run_command(f"sudo ip link set {interface} down")
        result = run_command(f"sudo ip link set {interface} address {mac}")
        run_command(f"sudo ip link set {interface} up")

        if result:
            logger.info(f"Spoofed MAC address to {mac} on {interface}")
            print(f"MAC address changed to {mac} on {interface}.")
            return True
        logger.error("Failed to spoof MAC address.")
        print("Error: Failed to spoof MAC address.")
        return False

def clear_logs_and_cache(clear_logs: bool = True, clear_temp: bool = True):
    """Clear system logs and cache with granular control."""
    logger.info("Clearing system logs and cache...")
    system = platform.system()
    user = getpass.getuser()

    if system == "Windows":
        if clear_logs:
            run_command("wevtutil el | ForEach-Object {wevtutil cl $_}", powershell=True)
            logger.info("Cleared Windows Event Logs")
        if clear_temp:
            temp_dir = os.environ.get("TEMP", os.path.expandvars("%TEMP%"))
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                os.makedirs(temp_dir, exist_ok=True)
                logger.info("Cleared Windows temporary files")
        print("Windows logs and temp files cleared.")
    elif system == "Darwin":
        if clear_logs:
            log_dirs = ["/private/var/log/system.log"]
            for log_file in log_dirs:
                if os.path.exists(log_file):
                    run_command(f"sudo truncate -s 0 {log_file}")
                    logger.info(f"Cleared log file: {log_file}")
        if clear_temp:
            if os.path.exists("/private/tmp"):
                shutil.rmtree("/private/tmp", ignore_errors=True)
                os.mkdir("/private/tmp")
                logger.info("Cleared /private/tmp directory")
        print("macOS logs and temp files cleared.")
    else:  # Linux
        if clear_logs:
            log_dirs = ["/var/log/syslog", "/var/log/messages", "/var/log/auth.log"]
            for log_file in log_dirs:
                if os.path.exists(log_file):
                    run_command(f"sudo truncate -s 0 {log_file}")
                    logger.info(f"Cleared log file: {log_file}")
        if clear_temp:
            if os.path.exists("/tmp"):
                shutil.rmtree("/tmp", ignore_errors=True)
                os.mkdir("/tmp")
                logger.info("Cleared /tmp directory")
        print("Linux logs and temp files cleared.")
    input("Press Enter to return to menu...")

def disable_webrtc(browsers: List[str]):
    """Disable WebRTC for specified browsers."""
    logger.info("Disabling WebRTC...")
    user = getpass.getuser()
    system = platform.system()

    for browser in browsers:
        if browser == "Firefox":
            profile_path = get_browser_paths().get("Firefox")
            if profile_path and os.path.exists(profile_path):
                profiles_ini = os.path.join(profile_path, "profiles.ini")
                if os.path.exists(profiles_ini):
                    profile = None
                    with open(profiles_ini, 'r') as f:
                        for line in f:
                            if line.startswith("Path="):
                                profile = line.strip().split("=")[1]
                                break
                    if profile:
                        prefs_js = os.path.join(profile_path, profile, "prefs.js")
                        webrtc_setting = 'user_pref("media.peerconnection.enabled", false);'
                        if os.path.exists(prefs_js):
                            with open(prefs_js, 'a') as f:
                                f.write(webrtc_setting + "\n")
                            logger.info(f"Disabled WebRTC for Firefox profile: {profile}")
                            print(f"WebRTC disabled for Firefox.")
                        else:
                            logger.error("Firefox prefs.js not found.")
                            print("Error: Firefox profile not found.")
                else:
                    logger.warning("Firefox profiles.ini not found.")
                    print("Firefox not found.")
            else:
                logger.warning("Firefox data directory not found.")
                print("Firefox not found.")
        else:
            prefs_path = get_browser_paths().get(browser)
            if prefs_path and os.path.exists(prefs_path):
                prefs_file = os.path.join(prefs_path, "Preferences")
                try:
                    with open(prefs_file, 'r') as f:
                        prefs = json.load(f)
                    prefs["webrtc"] = {"enabled": False}
                    with open(prefs_file, 'w') as f:
                        json.dump(prefs, f, indent=2)
                    logger.info(f"Disabled WebRTC for {browser}.")
                    print(f"WebRTC disabled for {browser}.")
                except Exception as e:
                    logger.error(f"Failed to modify {browser} preferences: {str(e)}")
                    print(f"Error: Failed to modify {browser} preferences.")
            else:
                logger.warning(f"{browser} preferences file not found.")
                print(f"{browser} not found.")
    input("Press Enter to return to menu...")

def randomize_user_agent(browsers: List[str]):
    """Randomize user agent for specified browsers."""
    logger.info("Randomizing user agents...")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
    ]
    user = getpass.getuser()

    for browser in browsers:
        if browser == "Firefox":
            profile_path = get_browser_paths().get("Firefox")
            if profile_path and os.path.exists(profile_path):
                profiles_ini = os.path.join(profile_path, "profiles.ini")
                if os.path.exists(profiles_ini):
                    profile = None
                    with open(profiles_ini, 'r') as f:
                        for line in f:
                            if line.startswith("Path="):
                                profile = line.strip().split("=")[1]
                                break
                    if profile:
                        prefs_js = os.path.join(profile_path, profile, "prefs.js")
                        new_user_agent = random.choice(user_agents)
                        user_agent_setting = f'user_pref("general.useragent.override", "{new_user_agent}");'
                        if os.path.exists(prefs_js):
                            with open(prefs_js, 'a') as f:
                                f.write(user_agent_setting + "\n")
                            logger.info(f"Set Firefox user agent to: {new_user_agent}")
                            print(f"Firefox user agent set to: {new_user_agent}")
                        else:
                            logger.error("Firefox prefs.js not found.")
                            print("Error: Firefox profile not found.")
                else:
                    logger.warning("Firefox profiles.ini not found.")
                    print("Firefox not found.")
            else:
                logger.warning("Firefox data directory not found.")
                print("Firefox not found.")
        else:
            prefs_path = get_browser_paths().get(browser)
            if prefs_path and os.path.exists(prefs_path):
                prefs_file = os.path.join(prefs_path, "Preferences")
                try:
                    with open(prefs_file, 'r') as f:
                        prefs = json.load(f)
                    new_user_agent = random.choice(user_agents)
                    prefs["custom_user_agent"] = new_user_agent
                    with open(prefs_file, 'w') as f:
                        json.dump(prefs, f, indent=2)
                    logger.info(f"Set {browser} user agent to: {new_user_agent}")
                    print(f"{browser} user agent set to: {new_user_agent}")
                except Exception as e:
                    logger.error(f"Failed to modify {browser} preferences: {str(e)}")
                    print(f"Error: Failed to modify {browser} preferences.")
            else:
                logger.warning(f"{browser} preferences file not found.")
                print(f"{browser} not found.")
    input("Press Enter to return to menu...")

def is_browser_running(browser_name: str) -> bool:
    """Check if a browser process is running."""
    browser_executables = {
        "Edge": ["msedge.exe"],
        "Chrome": ["chrome.exe"],
        "Opera": ["opera.exe"],
        "Opera GX": ["opera.exe"],
        "Brave": ["brave.exe"],
        "Firefox": ["firefox.exe"]
    }
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() in browser_executables.get(browser_name, []):
            return True
    return False

def ensure_browsers_closed(browsers: List[str]) -> bool:
    """Ensure specified browsers are closed."""
    browser_executables = {
        "Edge": ["msedge.exe"],
        "Chrome": ["chrome.exe"],
        "Opera": ["opera.exe"],
        "Opera GX": ["opera.exe"],
        "Brave": ["brave.exe"],
        "Firefox": ["firefox.exe"]
    }
    running_browsers = [b for b in browsers if is_browser_running(b)]
    if running_browsers:
        print(f"Error: The following browsers are running: {', '.join(running_browsers)}")
        choice = input("Close them automatically? (y/n): ").strip().lower()
        if choice == 'y':
            for browser in running_browsers:
                for proc in psutil.process_iter(['name', 'pid']):
                    if proc.info['name'].lower() in browser_executables.get(browser, []):
                        try:
                            if psutil.pid_exists(proc.info['pid']):
                                proc.terminate()
                                proc.wait(timeout=5)
                                logger.info(f"Terminated {proc.info['name']} (pid={proc.info['pid']}).")
                            else:
                                logger.info(f"Process {proc.info['name']} (pid={proc.info['pid']}) no longer exists.")
                        except psutil.NoSuchProcess:
                            logger.info(f"Process {proc.info['name']} (pid={proc.info['pid']}) no longer exists.")
                        except psutil.TimeoutExpired:
                            logger.error(f"Failed to terminate {proc.info['name']} (pid={proc.info['pid']}): Timeout.")
                            print(f"Error: {proc.info['name']} did not close properly.")
                        except psutil.Error as e:
                            logger.error(f"Failed to terminate {proc.info['name']} (pid={proc.info['pid']}): {str(e)}")
                            print(f"Error: Failed to terminate {proc.info['name']}.")
                time.sleep(1)
            still_running = [b for b in browsers if is_browser_running(b)]
            if still_running:
                print(f"Error: Could not close: {', '.join(still_running)}. Please close manually.")
                return False
        else:
            print("Please close the browsers and try again.")
            return False
    return True

def get_browser_paths() -> Dict[str, str]:
    """Get browser data paths."""
    user = getpass.getuser()
    system = platform.system()
    if system == "Windows":
        return {
            "Edge": os.path.expandvars(f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"),
            "Chrome": os.path.expandvars(f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default"),
            "Opera": os.path.expandvars(f"C:\\Users\\{user}\\AppData\\Roaming\\Opera Software\\Opera Stable"),
            "Opera GX": os.path.expandvars(f"C:\\Users\\{user}\\AppData\\Roaming\\Opera Software\\Opera GX Stable"),
            "Brave": os.path.expandvars(f"C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default"),
            "Firefox": os.path.expandvars(f"C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
        }
    elif system == "Linux":
        return {
            "Chrome": f"/home/{user}/.config/google-chrome/Default",
            "Opera": f"/home/{user}/.config/opera",
            "Brave": f"/home/{user}/.config/BraveSoftware/Brave-Browser/Default",
            "Firefox": f"/home/{user}/.mozilla/firefox"
        }
    elif system == "Darwin":
        home = os.path.expanduser("~")
        return {
            "Edge": f"{home}/Library/Application Support/Microsoft Edge/Default",
            "Chrome": f"{home}/Library/Application Support/Google/Chrome/Default",
            "Opera": f"{home}/Library/Application Support/com.operasoftware.Opera",
            "Brave": f"{home}/Library/Application Support/BraveSoftware/Brave-Browser/Default",
            "Firefox": f"{home}/Library/Application Support/Firefox/Profiles"
        }
    return {}

def clear_browser_data(browsers: List[str]):
    """Clear cookies and cache for specified browsers."""
    if not ensure_browsers_closed(browsers):
        input("Press Enter to return to menu...")
        return

    browser_paths = get_browser_paths()
    for browser in browsers:
        path = browser_paths.get(browser)
        if not path or not os.path.exists(path):
            logger.warning(f"{browser} data directory not found.")
            print(f"{browser} not found. Skipping...")
            continue

        if browser == "Firefox":
            clear_firefox_data(path)
            print(f"Cleared cookies and cache for {browser}.")
        else:
            cookies_path = os.path.join(path, "Cookies")
            cache_paths = [
                os.path.join(path, "Cache"),
                os.path.join(path, "Cache2"),
                os.path.join(path, "Code Cache"),
                os.path.join(path, "GPUCache"),
                os.path.join(path, "Service Worker", "CacheStorage")
            ]
            if os.path.exists(cookies_path):
                try:
                    os.remove(cookies_path)
                    logger.info(f"Cleared cookies for {browser}")
                    print(f"Cleared cookies for {browser}.")
                except PermissionError:
                    logger.error(f"Permission denied for {browser} cookies.")
                    print(f"Error: Permission denied for {browser} cookies.")
                except Exception as e:
                    logger.error(f"Failed to clear cookies for {browser}: {str(e)}")
                    print(f"Error: Failed to clear cookies for {browser}.")
            for cache_path in cache_paths:
                if os.path.exists(cache_path):
                    try:
                        shutil.rmtree(cache_path, ignore_errors=False)
                        logger.info(f"Cleared cache at {cache_path} for {browser}")
                        print(f"Cleared cache for {browser}.")
                    except PermissionError:
                        logger.error(f"Permission denied for {browser} cache.")
                        print(f"Error: Permission denied for {browser} cache.")
                    except Exception as e:
                        logger.error(f"Failed to clear cache at {cache_path}: {str(e)}")
                        print(f"Error: Failed to clear cache for {browser}.")
    input("Press Enter to return to menu...")

def clear_firefox_data(firefox_path: str):
    """Clear cookies and cache for all Firefox profiles."""
    if platform.system() in ["Windows", "Darwin"]:
        for profile in os.listdir(firefox_path):
            profile_path = os.path.join(firefox_path, profile)
            if os.path.isdir(profile_path):
                cookies_path = os.path.join(profile_path, "cookies.sqlite")
                cache_path = os.path.join(profile_path, "cache")
                cache2_path = os.path.join(profile_path, "cache2")
                try:
                    if os.path.exists(cookies_path):
                        os.remove(cookies_path)
                        logger.info(f"Cleared cookies for Firefox profile: {profile}")
                    if os.path.exists(cache_path):
                        shutil.rmtree(cache_path, ignore_errors=True)
                        logger.info(f"Cleared cache for Firefox profile: {profile}")
                    if os.path.exists(cache2_path):
                        shutil.rmtree(cache2_path, ignore_errors=True)
                        logger.info(f"Cleared cache2 for Firefox profile: {profile}")
                except PermissionError:
                    logger.error(f"Permission denied for Firefox profile: {profile}")
                    print(f"Error: Permission denied for Firefox profile {profile}.")
                except Exception as e:
                    logger.error(f"Failed to clear Firefox profile {profile}: {str(e)}")
                    print(f"Error: Failed to clear Firefox profile {profile}.")
    else:  # Linux
        profiles_ini = os.path.join(firefox_path, "profiles.ini")
        if os.path.exists(profiles_ini):
            profile_path = None
            with open(profiles_ini, 'r') as f:
                for line in f:
                    if line.startswith("Path="):
                        profile_path = line.strip().split("=")[1]
                        break
            if profile_path:
                full_profile_path = os.path.join(firefox_path, profile_path)
                cookies_path = os.path.join(full_profile_path, "cookies.sqlite")
                cache_path = os.path.join(full_profile_path, "cache")
                cache2_path = os.path.join(full_profile_path, "cache2")
                try:
                    if os.path.exists(cookies_path):
                        os.remove(cookies_path)
                        logger.info(f"Cleared cookies for Firefox profile: {profile_path}")
                    if os.path.exists(cache_path):
                        shutil.rmtree(cache_path, ignore_errors=True)
                        logger.info(f"Cleared cache for Firefox profile: {profile_path}")
                    if os.path.exists(cache2_path):
                        shutil.rmtree(cache2_path, ignore_errors=True)
                        logger.info(f"Cleared cache2 for Firefox profile: {profile_path}")
                except PermissionError:
                    logger.error(f"Permission denied for Firefox profile: {profile_path}")
                    print(f"Error: Permission denied for Firefox profile {profile_path}.")
                except Exception as e:
                    logger.error(f"Failed to clear Firefox profile {profile_path}: {str(e)}")
                    print(f"Error: Failed to clear Firefox profile {profile_path}.")

DESC="Perform a network privacy scan."
def network_privacy_scan():
    """Perform a network privacy scan."""
    logger.info("Performing network privacy scan...")
    print("Scanning network configuration...")

    # Check DNS settings
    dns_servers = []
    if platform.system() == "Windows":
        result = run_command("Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses", powershell=True)
        if result:
            dns_servers = result.splitlines()
    else:
        result = run_command("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'")
        if result:
            dns_servers = result.splitlines()

    print("DNS Servers:")
    for dns in dns_servers:
        try:
            ip = ipaddress.ip_address(dns)
            print(f" - {dns} ({'Public' if ip.is_global else 'Private'})")
        except ValueError:
            print(f" - {dns} (Invalid IP)")

    # Check for DNS leaks
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        public_ip = response.json().get("ip")
        print(f"Current Public IP: {public_ip}")
    except requests.RequestException as e:
        logger.error(f"Failed to check public IP: {str(e)}")
        print("Error: Unable to check public IP.")

    # Check open ports
    open_ports = []
    for port in [80, 443, 8080, 22, 3389]:  # Common ports
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    if open_ports:
        print(f"Open Ports: {', '.join(map(str, open_ports))}")
    else:
        print("No common ports open.")

    # Check current MAC address
    current_mac = getmac.get_mac_address()
    if current_mac:
        print(f"Current MAC Address: {current_mac}")
    else:
        print("Unable to retrieve current MAC address.")

    print("Network scan complete.")
    input("Press Enter to return to menu...")

def configure_dns_protection():
    """Configure DNS leak protection."""
    logger.info("Configuring DNS leak protection...")
    secure_dns = ["1.1.1.1", "8.8.8.8"]  # Cloudflare and Google DNS
    system = platform.system()

    if system == "Windows":
        adapter = run_command(
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*'} | Select-Object -First 1 | Select-Object -ExpandProperty Name",
            powershell=True
        )
        if adapter:
            for dns in secure_dns:
                run_command(f"Set-DnsClientServerAddress -InterfaceAlias '{adapter}' -ServerAddresses ('{dns}')", powershell=True)
            logger.info(f"Set DNS servers to {', '.join(secure_dns)} on {adapter}")
            print(f"DNS servers set to {', '.join(secure_dns)}.")
        else:
            logger.error("No active network adapter found.")
            print("Error: No active network adapter found.")
    else:
        resolv_conf = "/etc/resolv.conf"
        try:
            with open(resolv_conf, 'w') as f:
                for dns in secure_dns:
                    f.write(f"nameserver {dns}\n")
            logger.info(f"Updated {resolv_conf} with DNS servers: {', '.join(secure_dns)}")
            print(f"DNS servers set to {', '.join(secure_dns)}.")
        except PermissionError:
            logger.error(f"Permission denied writing to {resolv_conf}.")
            print("Error: Permission denied. Run as sudo.")
        except Exception as e:
            logger.error(f"Failed to update DNS: {str(e)}")
            print(f"Error: Failed to update DNS.")
    input("Press Enter to return to menu...")

def system_fingerprint_randomizer():
    """Randomize system fingerprint attributes."""
    logger.info("Randomizing system fingerprint...")
    
    # Randomize hostname
    if platform.system() != "Windows":
        new_hostname = f"host-{random.randint(1000, 9999)}"
        run_command(f"sudo hostnamectl set-hostname {new_hostname}")
        logger.info(f"Set hostname to {new_hostname}")
        print(f"Hostname set to {new_hostname}")

    # Randomize system time zone
    timezones = ["UTC", "America/New_York", "Europe/London", "Asia/Tokyo"]
    new_timezone = random.choice(timezones)
    if platform.system() == "Windows":
        run_command(f"Set-TimeZone -Id '{new_timezone}'", powershell=True)
    else:
        run_command(f"sudo timedatectl set-timezone {new_timezone}")
    logger.info(f"Set timezone to {new_timezone}")
    print(f"Timezone set to {new_timezone}")

    print("System fingerprint randomized.")
    input("Press Enter to return to menu...")

def configure_settings(config_manager: ConfigManager):
    """Configure tool settings interactively."""
    print("\nConfigure Settings:")
    print("1. Mullvad Account Number")
    print("2. VPN Rotation Interval (seconds)")
    print("3. Preferred VPN Countries (comma-separated)")
    print("4. Browsers to Clear")
    print("5. Clear System Logs (True/False)")
    print("6. Clear Temporary Files (True/False)")
    print("7. Auto-Spoof MAC Address (True/False)")
    print("8. Auto-Randomize User Agent (True/False)")
    print("9. Auto-Disable WebRTC (True/False)")
    print("10. Save and Return")

    config = config_manager.load_config()
    updates = {}
    
    while True:
        choice = input("Select an option (1-10): ")
        if choice == '1':
            account = input("Enter Mullvad account number: ").strip()
            updates.setdefault('mullvad', {})['account_number'] = account
        elif choice == '2':
            interval = input("Enter rotation interval in seconds (e.g., 300): ").strip()
            updates.setdefault('mullvad', {})['rotation_interval'] = interval
        elif choice == '3':
            countries = input("Enter preferred countries (e.g., us,ca,uk): ").strip()
            updates.setdefault('mullvad', {})['preferred_countries'] = countries
        elif choice == '4':
            browsers = input("Enter browsers to clear (e.g., Edge,Chrome,Firefox): ").strip()
            updates.setdefault('privacy', {})['browsers_to_clear'] = browsers
        elif choice == '5':
            clear_logs = input("Clear system logs? (True/False): ").strip()
            updates.setdefault('privacy', {})['clear_logs'] = clear_logs
        elif choice == '6':
            clear_temp = input("Clear temporary files? (True/False): ").strip()
            updates.setdefault('privacy', {})['clear_temp'] = clear_temp
        elif choice == '7':
            spoof_mac = input("Auto-spoof MAC address? (True/False): ").strip()
            updates.setdefault('network', {})['spoof_mac'] = spoof_mac
        elif choice == '8':
            randomize_ua = input("Auto-randomize user agent? (True/False): ").strip()
            updates.setdefault('network', {})['randomize_user_agent'] = randomize_ua
        elif choice == '9':
            disable_webrtc = input("Auto-disable WebRTC? (True/False): ").strip()
            updates.setdefault('network', {})['disable_webrtc'] = disable_webrtc
        elif choice == '10':
            config_manager.save_config(updates)
            print("Settings saved.")
            break
        else:
            print("Invalid option. Please select 1-10.")
        input("Press Enter to continue...")

def run_mullvad_rotator(config: configparser.ConfigParser):
    """Run the Mullvad IP rotator with configuration."""
    account_number = config['mullvad']['account_number']
    rotation_interval = int(config['mullvad']['rotation_interval'])
    preferred_countries = config['mullvad']['preferred_countries'].split(',')

    if not login_mullvad(account_number):
        logger.error("Login failed.")
        input("Press Enter to return to menu...")
        return

    servers = get_mullvad_servers(preferred_countries)
    if not servers:
        logger.error("No servers available.")
        input("Press Enter to return to menu...")
        return

    print(f"Starting Mullvad IP Rotator with {len(servers)} servers. Press Ctrl+C to stop.")
    try:
        while True:
            for server in servers:
                disconnect_vpn()
                if connect_to_server(server):
                    logger.info(f"Connected to {server}. Waiting {rotation_interval} seconds...")
                    time.sleep(rotation_interval)
                else:
                    logger.warning(f"Failed to connect to {server}. Trying next server...")
                    time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Rotator interrupted.")
        disconnect_vpn()
        print("Returning to menu...")
        time.sleep(1)

def main():
    """Main function to run the advanced anonymization tool."""
    check_admin_privileges()
    config_manager = ConfigManager(CONFIG_FILE)
    config = config_manager.load_config()

    while True:
        choice = display_menu()
        if choice == '1':
            run_mullvad_rotator(config)
        elif choice == '2':
            interface = input("Enter network interface (leave blank for default): ").strip() or None
            specific_mac = input("Enter specific MAC address (leave blank for random): ").strip() or None
            spoof_mac_address(interface, specific_mac)
        elif choice == '3':
            clear_logs = config.getboolean('privacy', 'clear_logs', fallback=True)
            clear_temp = config.getboolean('privacy', 'clear_temp', fallback=True)
            clear_logs_and_cache(clear_logs, clear_temp)
        elif choice == '4':
            browsers = config['privacy']['browsers_to_clear'].split(',')
            disable_webrtc(browsers)
        elif choice == '5':
            browsers = config['privacy']['browsers_to_clear'].split(',')
            randomize_user_agent(browsers)
        elif choice == '6':
            browsers = config['privacy']['browsers_to_clear'].split(',')
            clear_browser_data(browsers)
        elif choice == '7':
            network_privacy_scan()
        elif choice == '8':
            configure_settings(config_manager)
        elif choice == '9':
            configure_dns_protection()
        elif choice == '10':
            system_fingerprint_randomizer()
        elif choice == '11':
            logger.info("Exiting program.")
            print("Goodbye!")
            sys.exit(0)
        else:
            print("Invalid option. Please select 1-11.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        disconnect_vpn()
        sys.exit(1)
