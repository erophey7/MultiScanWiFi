# MultiScanWiFi

# MultiScanWiFi

MultiScanWiFi is a **multithreaded Wi-Fi scanner** that supports multiple interfaces simultaneously.  
It automatically scans access points (APs) and clients, captures WPA/WPA2 handshakes, performs deauthentication attacks (deauth), and provides a terminal-based interface with logging.

> ⚠️ **Warning:** Use this tool only on networks you own or have explicit permission to test. Unauthorized use may violate laws in your country.

---

## Features

- Scan multiple Wi-Fi interfaces at once
- Supports only **2.4 GHz Wi-Fi networks**
- Automatic channel hopping and scanning
- Capture WPA/WPA2 handshakes
- Logs results and supports terminal output with curses
- Configurable scan time, wait time, and deauth count
- Save captured handshakes in `.cap` files

---

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
- Wireless network interfaces capable of monitor mode and packet injection
- `ip` + `iw` **or** `ifconfig` + `iwconfig`

---

Usage

Run MultiScanWiFi with one or more interfaces:

```bash
sudo python3 multiscanwifi.py -i wlan0,wlan1 -s 5 -w 10 -o ./results/ -d 20
```

| Argument           | Description                                                  | Default      |
| ------------------ | ------------------------------------------------------------ | ------------ |
| `-i, --interfaces` | Comma-separated list of Wi-Fi interfaces (e.g., wlan0,wlan1) | **Required** |
| `-s, --scantime`   | Scan time per channel (seconds)                              | 5            |
| `-w, --waittime`   | Wait time between scans (seconds)                            | 10           |
| `-o, --out`        | Output folder to save results                                | `./out/`     |
| `-d, --deauth`     | Number of deauthentication packets per client                | 20           |

Example

Scan two interfaces with default settings:
`sudo python3 multiscanwifi.py -i wlan0,wlan1`
Scan a single interface with custom scan and wait times:
`sudo python3 multiscanwifi.py -i wlan0 -s 10 -w 5 -o ./captures/`
Limit deauthentication packets to 5:
`sudo python3 multiscanwifi.py -i wlan0 -d 5`

## Notes
- Deauthentication attacks may be illegal on networks you do not own.
