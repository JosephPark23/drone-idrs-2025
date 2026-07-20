#!/usr/bin/env python3
# packet capture for the drone IDS
# gets the 802.11 management frames for the target BSSID via tshark, one window at a time

'''
Why use tshark? You could argue that using an existing library, like scapy or even pyshark
would've been more efficient...

Simply put, for some of the functionalities I just couldn't get these libraries to work. Whether it was a limitation
of my programming skill or a legitimate incompatibility, I will never truly know (the former is much more likely), but
tshark is powerful and gets the job done. It also has very intuitive support with python.

'''

import logging
import platform
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional


def _to_int(text: str, default: int = -1) -> int:
    try:
        return int(text) if text else default
    except (ValueError, TypeError):
        return default


def _to_float(text: str, default=None):
    try:
        return float(text) if text else default
    except (ValueError, TypeError):
        return default


class Sniffer(threading.Thread):
    # background thread that ggvies a list of packet dictionaries to the `output` every window

    def __init__(
        self,
        interface: str,
        bssid: str,
        output: Callable[[List[Dict[str, Any]]], None],
        window_size: float = 1.0,
        channel: Optional[int] = None,
    ):
        super().__init__(daemon=True)

        self.interface = interface
        self.bssid = bssid.lower()
        self.output = output
        self.window_size = float(window_size)
        self.channel = channel

        self.stop_event = threading.Event()
        self.error_lock = threading.Lock()
        self.error: Optional[Exception] = None
        self.log = logging.getLogger("Sniffer")

        self.tshark_path = self._find_tshark()

        # channel locking is for linux only
        if platform.system() != "Windows":
            self._set_channel()

    def _find_tshark(self) -> str:
        if platform.system() == "Windows":
            win_path = r"C:\Program Files\Wireshark\tshark.exe"
            try:
                subprocess.run(
                    [win_path, "--version"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return win_path
            except (subprocess.CalledProcessError, FileNotFoundError):
                # not at the default install path, hope it's on PATH
                return "tshark"
        return "tshark"

    def _set_channel(self) -> None:
        if self.channel is None:
            return

        try:
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.channel)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.log.info(f"Locked to channel {self.channel}")
        except Exception as e:
            self.log.warning(f"Failed to set channel {self.channel}: {e}")

    def run(self) -> None:
        window_num = 0
        try:
            while not self.stop_event.is_set():
                window_num += 1
                packets = self._capture_window(window_num)

                try:
                    self.output(packets)
                except Exception as cb_err:
                    self.log.error(f"Error in output callback: {cb_err}")
                    with self.error_lock:
                        self.error = cb_err
                    break
        except Exception as e:
            with self.error_lock:
                self.error = e

    def _capture_window(self, window_num: int) -> List[Dict[str, Any]]:
        packets: List[Dict[str, Any]] = []

        display_filter = (
            f"wlan && ("
            f"wlan.sa == {self.bssid} || "
            f"wlan.da == {self.bssid} || "
            f"wlan.bssid == {self.bssid}"
            f")"
        )

        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-a", f"duration:{self.window_size}",
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=|",
            "-E", "occurrence=f",
            "-Y", display_filter,
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.bssid",
            "-e", "wlan.fc.type",
            "-e", "wlan.fc.subtype",
            "-e", "radiotap.dbm_antsignal",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.window_size + 2,
            )

            if result.stdout:
                lines = result.stdout.strip().split('\n')

                # first line is the header we asked for, skip it
                if len(lines) > 1:
                    for line in lines[1:]:
                        parsed = self._parse_tshark_fields(line)
                        if parsed:
                            packets.append(parsed)

        except subprocess.TimeoutExpired:
            self.log.warning(f"[Win {window_num}] tshark timeout")
        except Exception as e:
            self.log.error(f"[Win {window_num}] tshark error: {e}")

        return packets

    def _parse_tshark_fields(self, line: str) -> Optional[Dict[str, Any]]:
        try:
            parts = line.strip().split('|')

            if len(parts) < 7:
                return None

            timestamp_str, src_mac, dst_mac, bssid, fc_type_str, fc_subtype_str, signal_str = parts[:7]

            return {
                "timestamp": _to_float(timestamp_str, time.time()),
                "src_mac": src_mac.lower() if src_mac else None,
                "dst_mac": dst_mac.lower() if dst_mac else None,
                "bssid": bssid.lower() if bssid else None,
                "type": _to_int(fc_type_str),
                "subtype": _to_int(fc_subtype_str),
                "signal_dbm": _to_float(signal_str),
            }

        except Exception as e:
            return None

    def stop(self) -> None:
        self.stop_event.set()
