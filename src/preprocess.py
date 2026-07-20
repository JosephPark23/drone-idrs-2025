#!/usr/bin/env python3
# feature extraction for the deauth attack part of the IDS
# pulls per-window counts for deauth frames and unauthorized connection attempts

from typing import Any, Dict, List
import pandas as pd


def to_int(value):
    # turn whatever came off the wire into an int, or -1 if it won't convert
    try:
        return int(value)
    except (ValueError, TypeError):
        return -1


def is_broadcast(mac):
    if not mac:
        return False
    mac = mac.lower()
    if mac.startswith("ff:ff"):
        return True
    if mac.startswith("01:00:5e"):
        return True
    if mac.startswith("33:33"):
        return True
    if mac == "00:00:00:00:00:00":
        return True
    return False


def pct(part, whole):
    if whole > 0:
        return 100.0 * part / whole
    return 0.0


def extract_features(packets: List[Dict[str, Any]], authorized_macs: List[str] = None) -> pd.DataFrame:
    # build the set of MACs we trust: the drone/phone, the bssid, and broadcast
    auth_set = set()
    if authorized_macs:
        for mac in authorized_macs:
            if mac:
                auth_set.add(mac.lower())
    for pkt in packets:
        bssid = pkt.get("bssid")
        if bssid:
            auth_set.add(str(bssid).lower())
    auth_set.add("ff:ff:ff:ff:ff:ff")

    # counters (which all start at zero)
    n = len(packets)
    deauth_count = 0
    unauth_auth_count = 0
    unauth_assoc_req_count = 0
    unauth_reassoc_req_count = 0
    unauth_eapol_count = 0
    unauth_total_mgmt = 0
    unauth_packet_count = 0
    unauth_macs = set()

    for pkt in packets:
        frame_type = to_int(pkt.get("type"))
        subtype = to_int(pkt.get("subtype"))

        # deauth frame from anyone (meaning, type 0, subtype 12)
        if frame_type == 0 and subtype == 12:
            deauth_count += 1

        src_mac = pkt.get("src_mac")
        if src_mac:
            src_mac = str(src_mac).lower()
        else:
            src_mac = ""

        # skip anything from a device we recognize (or broadcast/empty)
        if not src_mac or is_broadcast(src_mac) or src_mac in auth_set:
            continue

        unauth_packet_count += 1
        unauth_macs.add(src_mac)

        if frame_type == 0:
            unauth_total_mgmt += 1
            if subtype == 11:
                unauth_auth_count += 1        # authentication
            elif subtype == 0:
                unauth_assoc_req_count += 1   # association request
            elif subtype == 2:
                unauth_reassoc_req_count += 1  # reassociation request
        elif frame_type == 2 and subtype >= 8:
            unauth_eapol_count += 1  # since we don't have EAPOL types here this is a rudimentary substitute (update?)

    features = {
        "packet_count": n,
        "deauth_count": deauth_count,
        "deauth_pct": pct(deauth_count, n),
        "unauth_auth_count": unauth_auth_count,
        "unauth_assoc_req_count": unauth_assoc_req_count,
        "unauth_reassoc_req_count": unauth_reassoc_req_count,
        "unauth_eapol_count": unauth_eapol_count,
        "unauth_total_mgmt": unauth_total_mgmt,
        "unauth_packet_pct": pct(unauth_packet_count, n),
        "unique_unauth_macs": len(unauth_macs),
    }

    return pd.DataFrame([features])
