#!/usr/bin/env python3
# rules-based detection for the drone IDS
# catches deauth attacks and unauthorized connection attempts (auth/assoc/eapol from unknown MACs)

from typing import Any, Dict, List
from preprocess import extract_features


class Rules:
    # thresholds default to something sensitive; tune them in config.yaml

    def __init__(
            self,
            authorized_macs: List[str],
            deauth_threshold: int = 1,
            unauth_auth_threshold: int = 2,
            unauth_assoc_threshold: int = 1,
            unauth_reassoc_threshold: int = 1,
            unauth_eapol_threshold: int = 3,
            unauth_total_mgmt_threshold: int = 5,
            unauth_packet_pct_threshold: float = 10.0,
    ):
        self.authorized_macs = []
        for mac in authorized_macs:
            if mac:
                self.authorized_macs.append(mac.lower())

        self.deauth_threshold = deauth_threshold
        self.unauth_auth_threshold = unauth_auth_threshold
        self.unauth_assoc_threshold = unauth_assoc_threshold
        self.unauth_reassoc_threshold = unauth_reassoc_threshold
        self.unauth_eapol_threshold = unauth_eapol_threshold
        self.unauth_total_mgmt_threshold = unauth_total_mgmt_threshold
        self.unauth_packet_pct_threshold = unauth_packet_pct_threshold

    # run one window through the rules, return violations (if any)
    def analyze_window(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        df_features = extract_features(packets, authorized_macs=self.authorized_macs)
        features = df_features.iloc[0].to_dict()

        violations = []

        # deauth: only count the ones aimed at our own devices
        deauth_count = self._count_targeted_deauths(packets)
        if deauth_count >= self.deauth_threshold:
            violations.append(
                f"DEAUTH_ATTACK: {deauth_count} deauth frames targeting authorized devices"
            )

        # the rest are all "unknown MAC is trying to talk to us" checks
        if features["unauth_auth_count"] >= self.unauth_auth_threshold:
            violations.append(
                f"UNAUTHORIZED_AUTH: {features['unauth_auth_count']:.0f} auth attempts from unauthorized device"
            )

        if features["unauth_assoc_req_count"] >= self.unauth_assoc_threshold:
            violations.append(
                f"UNAUTHORIZED_ASSOC: {features['unauth_assoc_req_count']:.0f} assoc attempts from unauthorized device"
            )

        if features["unauth_reassoc_req_count"] >= self.unauth_reassoc_threshold:
            violations.append(
                f"UNAUTHORIZED_REASSOC: {features['unauth_reassoc_req_count']:.0f} reassoc attempts from unauthorized device"
            )

        if features["unauth_eapol_count"] >= self.unauth_eapol_threshold:
            violations.append(
                f"UNAUTHORIZED_EAPOL: {features['unauth_eapol_count']:.0f} EAPOL frames from unauthorized device"
            )

        if features["unauth_total_mgmt"] >= self.unauth_total_mgmt_threshold:
            violations.append(
                f"UNAUTHORIZED_MGMT: {features['unauth_total_mgmt']:.0f} mgmt frames from unauthorized device"
            )

        if features["unauth_packet_pct"] >= self.unauth_packet_pct_threshold:
            violations.append(
                f"HIGH_UNAUTH_TRAFFIC: {features['unauth_packet_pct']:.1f}% of traffic from unauthorized device"
            )

        return {
            "ok": len(violations) == 0,
            "reasons": violations,
            "n_violations": len(violations),
            "features": features,
        }

    # deauth frame (type 0, subtype 12) whose destination is one of our devices
    def _count_targeted_deauths(self, packets: List[Dict[str, Any]]) -> int:
        count = 0
        auth_set = set(self.authorized_macs)

        for pkt in packets:
            if pkt.get("type") == 0 and pkt.get("subtype") == 12:
                dst_mac = pkt.get("dst_mac", "").lower()
                if dst_mac in auth_set:
                    count += 1

        return count


def create_rules_from_config(config: Dict[str, Any]) -> Rules:
    network_cfg = config.get("network", {})
    rules_cfg = config.get("rules", {})

    authorized_macs = []

    if network_cfg.get("drone_mac"):
        authorized_macs.append(network_cfg["drone_mac"])

    # phone_macs can be a list or a single string; phone_mac is the old single-value key
    if "phone_macs" in network_cfg:
        phone_macs = network_cfg["phone_macs"]
        if isinstance(phone_macs, list):
            authorized_macs.extend(phone_macs)
        else:
            authorized_macs.append(phone_macs)
    elif "phone_mac" in network_cfg:
        authorized_macs.append(network_cfg["phone_mac"])

    # drop any blanks
    clean_macs = []
    for mac in authorized_macs:
        if mac:
            clean_macs.append(mac)
    authorized_macs = clean_macs

    return Rules(
        authorized_macs=authorized_macs,
        deauth_threshold=rules_cfg.get("deauth_threshold", 1),
        unauth_auth_threshold=rules_cfg.get("unauth_auth_threshold", 2),
        unauth_assoc_threshold=rules_cfg.get("unauth_assoc_threshold", 1),
        unauth_reassoc_threshold=rules_cfg.get("unauth_reassoc_threshold", 1),
        unauth_eapol_threshold=rules_cfg.get("unauth_eapol_threshold", 3),
        unauth_total_mgmt_threshold=rules_cfg.get("unauth_total_mgmt_threshold", 5),
        unauth_packet_pct_threshold=rules_cfg.get("unauth_packet_pct_threshold", 10.0),
    )
