#!/usr/bin/python3
import sys
import time
import logging
import threading
import argparse
import os
from driveshake import interfaceMonitorMode, scanModeAuto, set_logger

# --------------- env ---------------
interfaces = []


# ---------------- Logger ----------------
logger = logging.getLogger("WiFiScanner")
if not logger.hasHandlers():
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(ch)
logger.setLevel(logging.INFO)

set_logger(logger)

# ---------------- Get channel ----------------
def get_channel(interface, count):
    channels_24 = [2, 5, 8, 11, 14]
    offset = interfaces.index(interface)
    idx = (offset + (count - 1) * len(interfaces)) % len(channels_24)
    return channels_24[idx]


# ---------------- Scan Manager ----------------
class ScanManager(threading.Thread):
    def __init__(self, interface, bssid_filter=None, essid_filter=None, ignore_bssid=None,
                 scantime=5, waittime=10, output_folder="./", deauth_count=10):
        super().__init__()
        self.interface = interface
        self.bssid_filter = bssid_filter or []
        self.essid_filter = essid_filter or []
        self.ignore_bssid = ignore_bssid or []
        self.scantime = scantime
        self.waittime = waittime
        self.output_folder = output_folder
        self.deauth_count = deauth_count
        self.stop_flag = False
        self.scan_count = 0


    def run(self):
        while not self.stop_flag:
            try:
                self.scan_count += 1
                channel = get_channel(self.interface, self.scan_count)
                logger.info(f"[MAIN] [THREAD] Scanning {self.interface} on channel {channel}")

                scanModeAuto(
                    self.interface,
                    self.bssid_filter,
                    self.essid_filter,
                    self.ignore_bssid,
                    channel,
                    self.scantime,
                    self.waittime,
                    self.output_folder,
                    self.deauth_count
                )
            except Exception as e:
                logger.error(f"[MAIN] [THREAD] Error during scan on {self.interface}: {e}")
            time.sleep(1)

    def stop(self):
        self.stop_flag = True

# ---------------- Main ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wi-Fi Scanner with multiple interfaces")
    parser.add_argument("--interfaces", "-i", type=str, required=True, help="Comma-separated list of interfaces, e.g., wlan0,wlan1")
    parser.add_argument("--scantime", "-s", type=int, default=5, help="Time to scan a single channel (seconds)")
    parser.add_argument("--waittime", "-w", type=int, default=10, help="Time to wait between scans (seconds)")
    parser.add_argument("--out", "-o", type=str, default="./out/", help="Folder to save the results")
    parser.add_argument("--deauth", "-d", type=int, default=20, help="Number of deauthentication packets to send during scanning")
    args = parser.parse_args()

    interfaces_list = [iface.strip() for iface in args.interfaces.split(",") if iface.strip()]

    if not interfaces_list:
        logger.error("[MAIN] [IFACE] Interfaces not specified. Exit.")
        sys.exit(1)


    if not os.path.exists(args.out):
        os.makedirs(args.out)
        logger.info(f"[MAIN] Output folder has been created: {args.out}")

    # Enable monitoring on interfaces
    for iface in interfaces_list:
        if interfaceMonitorMode(iface) is None:
            logger.info(f"[MAIN] [IFACE] {iface}: Monitor mode enabled")
            interfaces.append(iface)
        else:
            logger.error(f"[MAIN] [IFACE] Failed to set monitor mode on {iface}")

    if not interfaces:
        logger.error("[MAIN] [IFACE] No interfaces available. Exit.")
        sys.exit(1)

    scanners = [
        ScanManager(
            iface,
            scantime=args.scantime,
            waittime=args.waittime,
            output_folder=args.out,
            deauth_count=args.deauth
        )
        for iface in interfaces
    ]

    try:
        for scanner in scanners:
            scanner.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[MAIN] [THREAD] Stopping all scans...")
        for scanner in scanners:
            scanner.stop()
        for scanner in scanners:
            scanner.join()
