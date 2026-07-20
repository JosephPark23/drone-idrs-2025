#!/usr/bin/env python3
# main user CLI script

import argparse
import logging
import platform
import subprocess
import sys
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from classify import create_classification
from sniffer import Sniffer


def timestamp() -> str:
    # local time, right down to the millisecond
    millis = int((time.time() % 1) * 1000)
    return time.strftime("%Y-%m-%d %H:%M:%S.") + f"{millis:03d}"


class AlertEngine:
    # alerts and statistics displays

    def __init__(
            self,
            interface: str,
            drone_bssid: str,
            authorized_macs: List[str],
            show_violations: bool = True,
            summary_interval: int = 30,
            alert_cooldown: float = 3.0,
    ):
        self.interface = interface
        self.drone_bssid = drone_bssid
        self.authorized_macs = set(mac.lower() for mac in authorized_macs)
        self.show_violations = show_violations
        self.summary_interval = summary_interval
        self.alert_cooldown = alert_cooldown
        self.fusion = None

        # stats
        self.total_windows = 0
        self.total_alerts = 0
        self.total_benign = 0

        # alert variables
        self.in_alert = False
        self.alert_start_time = None
        self.last_attack_time = None
        self.alert_violations = []
        self.attacker_macs = set()

        # alert tracking
        self.recent_alert_times = deque(maxlen=100)
        self.recent_violations = deque(maxlen=100)
        self.last_summary = time.time()

        # session logging (for the log files)
        self.session_start = datetime.now()
        self.session_log = []

        self.log = logging.getLogger("AlertEngine")

    # print a message and keep a copy for the session log
    def _emit(self, msg: str):
        print(msg)
        self.session_log.append(msg)

    # get a packet window and run it through the analyzer (rules_analyze)
    def handle_window(self, packets: List[Dict[str, Any]]):
        if not packets:
            return

        self.total_windows += 1
        now = time.time()
        result = self.fusion.analyze_window(packets)

        if result["final_label"] == "ATTACK":
            self.total_alerts += 1
            self.recent_alert_times.append(now)
            self.last_attack_time = now

            # num. of violations
            for violation in result["rules_violations"]:
                self.recent_violations.append(violation.split(":")[0])

            attacker_macs = self._extract_attacker_macs(packets, result)

            # new attack starts an alert, an ongoing one just gets updated
            if not self.in_alert:
                self._start_alert(result, attacker_macs)
            else:
                self._update_alert(result, attacker_macs)

        else:
            self.total_benign += 1

            # drop the alert once we've gone quiet long enough
            if self.in_alert and now - self.last_attack_time >= self.alert_cooldown:
                self._end_alert()

        # occasional stats summary (interval set in config.yaml)
        if now - self.last_summary >= self.summary_interval:
            self._print_summary()

    def _extract_attacker_macs(
            self,
            packets: List[Dict[str, Any]],
            result: Dict[str, Any]
    ) -> set:
        attacker_macs = set()

        violations = result.get("rules_violations", [])
        has_unauth = False
        for v in violations:
            if "UNAUTHORIZED" in v:
                has_unauth = True
                break

        # pull out unauthorized (non-broadcast) source MACs as the attackers
        if has_unauth:
            for pkt in packets:
                src_mac = pkt.get("src_mac", "").lower()
                if src_mac and src_mac not in self.authorized_macs and not self._is_broadcast(src_mac):
                    attacker_macs.add(src_mac)

        return attacker_macs

    def _is_broadcast(self, mac: str) -> bool:
        if not mac:
            return False
        if mac.startswith("ff:ff"):
            return True
        if mac.startswith("01:00:5e"):
            return True
        if mac.startswith("33:33"):
            return True
        if mac == "00:00:00:00:00:00":
            return True
        return False

    # open a fresh alert and also start the response
    def _start_alert(self, result: Dict[str, Any], attacker_macs: set):
        self.in_alert = True
        self.alert_start_time = time.time()
        self.alert_violations = result["rules_violations"]
        self.attacker_macs = attacker_macs

        alert_msg = (
            "\n" + "=" * 80 + "\n"
            f"[{timestamp()}] [ALERT] DEAUTH ATTACK DETECTED\n"
            "=" * 80 + "\n"
            f"  Detection:   Rules-Based\n"
            f"  Violations:  {len(self.alert_violations)}\n"
        )

        if self.show_violations:
            alert_msg += "\n  Rule Violations:\n"
            for v in self.alert_violations[:10]:
                alert_msg += f"    • {v}\n"
            if len(self.alert_violations) > 10:
                alert_msg += f"    ... and {len(self.alert_violations) - 10} more\n"

        if attacker_macs:
            alert_msg += f"\n  Attacker MACs: {', '.join(sorted(attacker_macs))}\n"
            self._deauth_attackers(attacker_macs)

        alert_msg += "\n  [ONGOING] Attack in progress [!]\n"
        alert_msg += "=" * 80 + "\n"

        self._emit(alert_msg)

    # if new attacker MACs show up mid-alert, log them and deauth them too
    def _update_alert(self, result: Dict[str, Any], attacker_macs: set):
        new_macs = attacker_macs - self.attacker_macs
        if new_macs:
            self.attacker_macs.update(new_macs)
            update_msg = f"[{timestamp()}] [ALERT] New attacker MAC(s) detected: {', '.join(sorted(new_macs))}\n"
            self._emit(update_msg)
            self._deauth_attackers(new_macs)

    # close out the alert once the cooldown has passed
    def _end_alert(self):
        if not self.in_alert:
            return

        duration = time.time() - self.alert_start_time
        if self.attacker_macs:
            attackers = ', '.join(sorted(self.attacker_macs))
        else:
            attackers = 'Unknown'

        end_msg = (
            "\n" + "=" * 80 + "\n"
            f"[{timestamp()}] [ALERT] Attack ended\n"
            "=" * 80 + "\n"
            f"  Duration:    {duration:.1f} seconds\n"
            f"  Attackers:   {attackers}\n"
            "=" * 80 + "\n"
        )

        self._emit(end_msg)

        self.in_alert = False
        self.alert_start_time = None
        self.alert_violations = []
        self.attacker_macs = set()

    # use aireplay-ng to get the attackers off the drone (linux only)
    def _deauth_attackers(self, attacker_macs: set):
        if platform.system() == "Windows":
            return

        for attacker_mac in attacker_macs:
            cmd = [
                "aireplay-ng", "--deauth", "10",
                "-a", self.drone_bssid,
                "-c", attacker_mac,
                self.interface,
            ]
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._emit(f"  [RESPONSE] Deauthenticating {attacker_mac}\n")
            except Exception as e:
                self.log.warning(f"Failed to deauth {attacker_mac}: {e}")

    def _print_summary(self):
        now = time.time()
        self.last_summary = now

        # how many alerts fired in the last minute
        alerts_per_min = 0
        for t in self.recent_alert_times:
            if now - t < 60:
                alerts_per_min += 1

        top = Counter(self.recent_violations).most_common(3)
        if top:
            top_parts = []
            for name, count in top:
                top_parts.append(f"{name}×{count}")
            top_str = ", ".join(top_parts)
        else:
            top_str = "none"

        if self.total_windows > 0:
            detection_rate = 100 * self.total_alerts / self.total_windows
        else:
            detection_rate = 0

        summary_msg = (
            f"\n[{time.strftime('%H:%M:%S')}] [STATS] "
            f"Windows: {self.total_windows}, "
            f"Attacks: {self.total_alerts} ({detection_rate:.1f}%), "
            f"Benign: {self.total_benign}, "
            f"Rate: {alerts_per_min}/min, "
            f"Top: {top_str}\n"
        )

        self._emit(summary_msg)

    # write everything we printed this session out to logs/
    def save_session_log(self):
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)

        timestamp = self.session_start.strftime("%Y%m%d_%H%M%S")
        log_file = logs_dir / f"ids_session_{timestamp}.log"

        session_duration = (datetime.now() - self.session_start).total_seconds()
        if self.total_windows > 0:
            detection_rate = self.total_alerts / self.total_windows * 100
        else:
            detection_rate = 0

        with log_file.open("w") as f:
            f.write("=" * 80 + "\n")
            f.write("DJI DRONE IDS - SESSION LOG\n")
            f.write("=" * 80 + "\n")
            f.write(f"Session Start: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Session End:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration:      {session_duration:.1f} seconds\n")
            f.write(f"\n")
            f.write(f"Statistics:\n")
            f.write(f"  Total Windows:  {self.total_windows}\n")
            f.write(f"  Attack Windows: {self.total_alerts}\n")
            f.write(f"  Benign Windows: {self.total_benign}\n")
            f.write(f"  Detection Rate: {detection_rate:.1f}%\n")
            f.write(f"\n")
            f.write("=" * 80 + "\n")
            f.write("SESSION EVENTS\n")
            f.write("=" * 80 + "\n\n")

            for entry in self.session_log:
                f.write(entry)

        print(f"\n[INFO] Session log saved to {log_file}")


def load_config(path: str) -> Dict[str, Any]:
    cfg_path = Path(path).expanduser().resolve()

    if not cfg_path.exists():
        raise FileNotFoundError(f"Config file not found: {cfg_path}")

    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    base = Path(cfg.get("base_path", cfg_path.parent)).resolve()
    if not base.exists():
        raise FileNotFoundError(f"Base path does not exist: {base}")

    return cfg


def run_live(cfg: Dict[str, Any]):
    sniffer_cfg = cfg.get("sniffer", {})
    network_cfg = cfg.get("network", {})
    alerts_cfg = cfg.get("alerts", {})

    interface = sniffer_cfg.get("interface")
    bssid = sniffer_cfg.get("bssid")
    drone_mac = network_cfg.get("drone_mac")

    if not all([interface, bssid, drone_mac]):
        raise ValueError(
            "Required config: sniffer.interface, sniffer.bssid, network.drone_mac"
        )

    phone_macs = []
    if "phone_macs" in network_cfg:
        pm = network_cfg["phone_macs"]
        if isinstance(pm, list):
            phone_macs = pm
        else:
            phone_macs = [pm]
    elif "phone_mac" in network_cfg:
        phone_macs = [network_cfg["phone_mac"]]

    authorized_macs = [drone_mac] + phone_macs

    fusion = create_classification(cfg)

    engine = AlertEngine(
        interface=interface,
        drone_bssid=bssid,
        authorized_macs=authorized_macs,
        show_violations=alerts_cfg.get("show_rule_violations", True),
        summary_interval=alerts_cfg.get("summary_interval", 30),
        alert_cooldown=alerts_cfg.get("alert_cooldown", 3.0),
    )
    engine.fusion = fusion

    print("\n" + "=" * 80)
    print("DJI DRONE WI-FI INTRUSION DETECTION SYSTEM")
    print("Rules-Based Detection: Deauth + Unauthorized Connection Attempts")
    print("=" * 80)
    print(f"Target BSSID:    {bssid}")
    print(f"Interface:       {interface}")
    print(f"Window Size:     {sniffer_cfg.get('window_size', 1.0)}s")

    if sniffer_cfg.get("channel"):
        print(f"Channel:         {sniffer_cfg['channel']}")

    print(f"\nAuthorized Devices:")
    print(f"  Drone:  {drone_mac}")
    for i, mac in enumerate(phone_macs, 1):
        print(f"  Phone {i}: {mac}")

    print(f"\nDetection Criteria:")
    print(f"  - Deauthentication frames targeting authorized devices")
    print(f"  - Unauthorized connection attempts")

    if platform.system() != "Windows":
        print(f"\nActive Response: Enabled (deauth attackers)")
    else:
        print(f"\nActive Response: Disabled (Windows)")

    print("\n" + "=" * 80)
    print("\nStarting capture...")

    sniffer = Sniffer(
        interface=interface,
        bssid=bssid,
        output=engine.handle_window,
        window_size=sniffer_cfg.get("window_size", 1.0),
        channel=sniffer_cfg.get("channel"),
    )

    sniffer.start()

    # give tshark a moment to come up before we check it's alive
    time.sleep(0.5)

    if sniffer.is_alive():
        print("[INFO] Tshark capture started successfully!")
        print("[INFO] Press Ctrl+C to stop\n")
    else:
        raise RuntimeError("Failed to start sniffer")

    try:
        while sniffer.is_alive():
            sniffer.join(1)
            if sniffer.error:
                raise RuntimeError(f"Sniffer error: {sniffer.error}")
    except KeyboardInterrupt:
        print("\n\n[INFO] Stopping IDS...")
        sniffer.stop()
        sniffer.join(timeout=5)
        print("[INFO] IDS stopped successfully\n")

        print("=" * 80)
        print("FINAL STATISTICS")
        print("=" * 80)
        print(f"Total Windows:  {engine.total_windows}")
        print(f"Total Attacks:  {engine.total_alerts}")
        print(f"Benign Windows: {engine.total_benign}")
        if engine.total_windows > 0:
            detection_rate = (engine.total_alerts / engine.total_windows * 100)
            print(f"Detection Rate: {detection_rate:.1f}%")
        print("=" * 80 + "\n")

        engine.save_session_log()


def main():
    parser = argparse.ArgumentParser(
        description="DJI Drone Wi-Fi Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config",
        default="config/config.yaml",
        help="Path to configuration file (default: config/config.yaml)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(levelname)s] %(message)s"
    )

    try:
        cfg = load_config(args.config)
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Failed to load config: {e}\n")
        sys.exit(1)

    try:
        run_live(cfg)
    except Exception as e:
        print(f"\n[ERROR] {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
