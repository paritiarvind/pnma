"""The detection rule set.

Each rule states what it saw, why it matters, what the *benign* explanation
would be, and what to do next. The benign explanation is not politeness -- it
is the thing that stops an operator either panicking or, far more commonly,
learning to dismiss the dashboard entirely.
"""

from __future__ import annotations

import json
import time

from ..collectors.portscan import C2_INDICATOR_PORTS, classify_port
from ..oui import describe as describe_vendor
from ..oui import is_iot_vendor
from .base import Detection, DetectionContext, Finding, downgrade, upgrade
from .host_rules import host_rules
from .identity_rules import identity_rules


# ---------------------------------------------------------------------------
# 1. New device on the network
# ---------------------------------------------------------------------------
class NewDeviceDetection(Detection):
    rule_id = "new_device"
    name = "Previously unseen device joined the network"
    severity = "medium"
    mitre_id = "T1200"
    mitre_name = "Hardware Additions"
    blind_spots = (
        "A device that never sends DHCP and never talks to this host may not be "
        "seen at all. A device on a wired switch port that this host never "
        "exchanges traffic with is invisible without a mirror port."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        if ctx.in_learning_mode:
            # On a fresh install every device is new. Alerting on all of them
            # produces a wall of noise that teaches the operator to ignore it.
            return []

        findings: list[Finding] = []
        rows = ctx.db.query(
            """SELECT d.* FROM devices d
               WHERE d.trusted = 0
                 AND d.first_seen >= ?
               ORDER BY d.first_seen DESC""",
            (ctx.now - 86400,),
        )

        for row in rows:
            mac = row["mac"] or ""
            randomised = row["mac_type"] == "local"
            has_fingerprint = bool(row["dhcp_fingerprint"])

            severity = self.severity
            confidence_note = ""

            if randomised and not has_fingerprint:
                # We cannot tell "new device" from "known phone, new MAC".
                # Saying so is more useful than a confident wrong answer.
                severity = downgrade(severity, 2)
                confidence_note = (
                    "\n\nLOW CONFIDENCE: this device is using a randomised MAC "
                    "address and has not yet been seen sending DHCP, so PNMA "
                    "cannot distinguish a genuinely new device from a known "
                    "phone that has rotated its address. Confidence will "
                    "improve when it renews its lease."
                )
            elif randomised and has_fingerprint:
                severity = downgrade(severity, 1)
                confidence_note = (
                    "\n\nMEDIUM CONFIDENCE: identity is derived from the DHCP "
                    "fingerprint rather than the MAC, which survives rotation."
                )

            if is_iot_vendor(mac):
                severity = upgrade(severity, 1)
                confidence_note += (
                    "\n\nThis OUI belongs to an IoT vendor. IoT devices are "
                    "disproportionately shipped with default credentials and "
                    "unpatched firmware."
                )

            vendor = describe_vendor(mac) if mac else "unknown"
            label = row["hostname"] or row["label"] or "unnamed"

            findings.append(
                Finding(
                    dedup_key=f"new_device:{row['device_id']}",
                    severity=severity,
                    title=f"New device: {label} ({vendor})",
                    description=(
                        f"A device not previously seen on this network appeared at "
                        f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(row['first_seen']))}.\n\n"
                        f"  MAC       {mac} ({row['mac_type']})\n"
                        f"  Vendor    {vendor}\n"
                        f"  IP        {row['ip'] or 'not yet observed'}\n"
                        f"  Hostname  {row['hostname'] or 'not advertised'}\n"
                        f"{confidence_note}\n\n"
                        "BENIGN EXPLANATION: a guest joined the Wi-Fi, you set up "
                        "new hardware, or a device that had been off for a long "
                        "time came back.\n\n"
                        "NEXT STEP: if you recognise it, mark it trusted to stop "
                        "this alert. If you do not, check your router's client "
                        "list and change the Wi-Fi password."
                    ),
                    device_id=row["device_id"],
                    evidence={
                        "mac": mac,
                        "mac_type": row["mac_type"],
                        "vendor": vendor,
                        "ip": row["ip"],
                        "hostname": row["hostname"],
                        "dhcp_fingerprint": row["dhcp_fingerprint"],
                        "first_seen": row["first_seen"],
                    },
                    # An unrecognised device is exactly what we want a port
                    # inventory for.
                    triggers_triage_scan=True,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# 2. ARP spoofing / MAC-IP binding anomalies
# ---------------------------------------------------------------------------
class ArpSpoofDetection(Detection):
    rule_id = "arp_spoof"
    name = "MAC/IP binding anomaly (possible ARP cache poisoning)"
    severity = "high"
    mitre_id = "T1557.002"
    mitre_name = "Adversary-in-the-Middle: ARP Cache Poisoning"
    blind_spots = (
        "Only bindings observed passively are considered. An attack conducted "
        "entirely between two other hosts, with no gratuitous ARP reaching this "
        "host, will not be seen without a mirror port."
    )

    # A DHCP lease handover legitimately moves an IP to a different MAC. Real
    # poisoning flips the binding back and forth rapidly; a lease change happens
    # once and sticks.
    FLAP_WINDOW_S = 600
    MIN_FLAPS = 3

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        gateway_ip = self._gateway_ip(ctx)

        # (a) One IP claimed by several MACs recently -- only counting
        #     *passively observed* claims, so our own ARP sweeps are excluded.
        contested = ctx.db.query(
            """SELECT ip, COUNT(DISTINCT mac) AS mac_count,
                      GROUP_CONCAT(mac) AS macs
               FROM bindings
               WHERE last_seen >= ? AND passive_count > 0
               GROUP BY ip
               HAVING mac_count > 1""",
            (ctx.now - self.FLAP_WINDOW_S,),
        )

        for row in contested:
            macs = sorted(set((row["macs"] or "").split(",")))
            is_gateway = row["ip"] == gateway_ip
            severity = "critical" if is_gateway else self.severity

            gateway_note = (
                "\n\nTHIS IS THE DEFAULT GATEWAY. If an attacker controls the "
                "gateway binding, all traffic leaving this network can be "
                "intercepted. Treat as urgent."
                if is_gateway
                else ""
            )

            findings.append(
                Finding(
                    dedup_key=f"arp_spoof:{row['ip']}:{','.join(macs)}",
                    severity=severity,
                    title=(
                        f"{'GATEWAY ' if is_gateway else ''}IP {row['ip']} claimed "
                        f"by {row['mac_count']} different MAC addresses"
                    ),
                    description=(
                        f"Within the last {self.FLAP_WINDOW_S // 60} minutes, "
                        f"{row['ip']} was claimed by:\n"
                        + "".join(
                            f"  {m}  ({describe_vendor(m)})\n" for m in macs if m
                        )
                        + gateway_note
                        + "\n\nBENIGN EXPLANATION: a DHCP lease was reassigned to a "
                        "different device, or a device with dual interfaces "
                        "(Wi-Fi and Ethernet) switched connection. Both of those "
                        "happen once and then settle.\n\n"
                        "MALICIOUS EXPLANATION: ARP cache poisoning, in which an "
                        "attacker forges replies to place themselves between two "
                        "hosts. This typically shows repeated, rapid flapping "
                        "rather than a single clean handover.\n\n"
                        "NEXT STEP: compare the MACs above with your router's "
                        "client list. Run 'arp -a' and check whether the gateway "
                        "entry matches the MAC recorded in your PNMA config."
                    ),
                    evidence={
                        "ip": row["ip"],
                        "macs": macs,
                        "is_gateway": is_gateway,
                        "vendors": {m: describe_vendor(m) for m in macs if m},
                    },
                )
            )

        # (b) The configured gateway MAC changed. The scope guard treats this as
        #     fatal; the detector records it as evidence.
        if gateway_ip:
            current = ctx.db.query_one(
                """SELECT mac, last_seen FROM bindings
                   WHERE ip = ? ORDER BY last_seen DESC LIMIT 1""",
                (gateway_ip,),
            )
            expected = self._expected_gateway_mac(ctx)
            if current and expected and current["mac"] != expected:
                findings.append(
                    Finding(
                        dedup_key=f"gateway_mac_change:{expected}:{current['mac']}",
                        severity="critical",
                        title="Gateway MAC address changed",
                        description=(
                            f"The gateway {gateway_ip} is configured as {expected} "
                            f"but is currently answering as {current['mac']} "
                            f"({describe_vendor(current['mac'])}).\n\n"
                            "BENIGN EXPLANATION: you replaced your router, your ISP "
                            "swapped the hardware, or the router failed over to a "
                            "different interface.\n\n"
                            "MALICIOUS EXPLANATION: an attacker is impersonating "
                            "your gateway to intercept traffic.\n\n"
                            "NEXT STEP: if you did not change your router, treat "
                            "this network as untrusted until resolved. If you did, "
                            "update gateway_mac in config/pnma.toml -- until you "
                            "do, the scope guard will refuse to scan."
                        ),
                        evidence={
                            "expected": expected,
                            "observed": current["mac"],
                            "observed_vendor": describe_vendor(current["mac"]),
                        },
                    )
                )
        return findings

    @staticmethod
    def _gateway_ip(ctx: DetectionContext) -> str | None:
        row = ctx.db.query_one("SELECT value FROM meta WHERE key = 'gateway_ip'")
        return row["value"] if row else None

    @staticmethod
    def _expected_gateway_mac(ctx: DetectionContext) -> str | None:
        row = ctx.db.query_one("SELECT value FROM meta WHERE key = 'gateway_mac'")
        return row["value"] if row else None


# ---------------------------------------------------------------------------
# 3. Service drift and risky exposure
# ---------------------------------------------------------------------------
class ServiceDriftDetection(Detection):
    rule_id = "service_drift"
    name = "New listening service appeared on a device"
    severity = "medium"
    mitre_id = "T1046"
    mitre_name = "Network Service Discovery"
    blind_spots = (
        "Only the top-N TCP ports are scanned, and UDP services are not scanned "
        "at all. A service on a high or unusual port will be missed."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        rows = ctx.db.query(
            """SELECT p.*, d.hostname, d.label, d.mac, d.ip, d.trusted
               FROM ports p JOIN devices d ON d.device_id = p.device_id
               WHERE p.closed_at IS NULL AND p.first_seen >= ?""",
            (ctx.now - 86400,),
        )

        for row in rows:
            risk, explanation = classify_port(row["port"])
            if risk is None:
                continue

            severity = {"high": "high", "medium": "medium", "low": "low"}[risk]
            name = row["label"] or row["hostname"] or row["ip"] or row["device_id"]

            findings.append(
                Finding(
                    dedup_key=f"service:{row['device_id']}:{row['port']}:{row['proto']}",
                    severity=severity,
                    title=f"{name} is listening on {row['port']}/{row['proto']}"
                    + (f" ({row['service']})" if row["service"] else ""),
                    description=(
                        f"A new listening service was found on {name} "
                        f"({row['ip'] or 'unknown IP'}).\n\n"
                        f"  Port     {row['port']}/{row['proto']}\n"
                        f"  Service  {row['service'] or 'unidentified'}\n"
                        f"  Product  {row['product'] or 'not probed'}\n\n"
                        f"WHY THIS MATTERS: {explanation}\n\n"
                        "BENIGN EXPLANATION: you deliberately enabled this "
                        "service, or a firmware update turned it on.\n\n"
                        "NEXT STEP: if you did not enable it, disable it in the "
                        "device settings. If you cannot, consider isolating the "
                        "device on a guest network."
                    ),
                    device_id=row["device_id"],
                    evidence={
                        "port": row["port"],
                        "proto": row["proto"],
                        "service": row["service"],
                        "product": row["product"],
                        "risk": risk,
                        "ip": row["ip"],
                    },
                    correlation_key=f"port:{row['device_id']}:{row['port']}",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# 4. C2 / backdoor indicators
# ---------------------------------------------------------------------------
class C2IndicatorDetection(Detection):
    rule_id = "c2_indicator"
    name = "Service associated with backdoors or command-and-control"
    severity = "critical"
    mitre_id = "T1571"
    mitre_name = "Non-Standard Port"
    blind_spots = (
        "This detects a device LISTENING on a C2-associated port. It cannot "
        "detect outbound C2 beaconing or data exfiltration: on a switched "
        "network this host does not see other devices' traffic. Egress "
        "visibility requires a local DNS resolver, router NetFlow, or inline "
        "placement -- see THREAT_MODEL.md, 'Visibility limits'."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        placeholders = ",".join("?" * len(C2_INDICATOR_PORTS))
        rows = ctx.db.query(
            f"""SELECT p.*, d.hostname, d.label, d.ip, d.mac
                FROM ports p JOIN devices d ON d.device_id = p.device_id
                WHERE p.closed_at IS NULL AND p.port IN ({placeholders})""",
            tuple(sorted(C2_INDICATOR_PORTS)),
        )

        for row in rows:
            _, explanation = classify_port(row["port"])
            name = row["label"] or row["hostname"] or row["ip"] or row["device_id"]
            findings.append(
                Finding(
                    dedup_key=f"c2:{row['device_id']}:{row['port']}",
                    severity=self.severity,
                    title=f"POSSIBLE COMPROMISE: {name} listening on {row['port']}/tcp",
                    description=(
                        f"{name} ({row['ip']}) is accepting connections on port "
                        f"{row['port']}, which is strongly associated with "
                        f"backdoors or command-and-control.\n\n"
                        f"WHY THIS MATTERS: {explanation}\n\n"
                        "BENIGN EXPLANATION: a developer tool, a game server, or "
                        "a deliberately configured service. Verify before acting.\n\n"
                        "NEXT STEP: isolate this device from the network, then "
                        "investigate. Do not simply close the port -- if the "
                        "device is compromised, the listener is a symptom rather "
                        "than the cause.\n\n"
                        "NOTE ON COVERAGE: PNMA sees that this device is "
                        "listening. It cannot see whether the device is sending "
                        "data out, because a host on a switched network does not "
                        "receive other devices' traffic."
                    ),
                    device_id=row["device_id"],
                    evidence={
                        "port": row["port"],
                        "service": row["service"],
                        "product": row["product"],
                        "ip": row["ip"],
                        "mac": row["mac"],
                    },
                    correlation_key=f"port:{row['device_id']}:{row['port']}",
                    triggers_triage_scan=True,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# 5. Availability / SLO
# ---------------------------------------------------------------------------
class AvailabilityDetection(Detection):
    rule_id = "availability"
    name = "Device unreachable or degraded"
    severity = "low"
    mitre_id = None
    mitre_name = None
    blind_spots = (
        "A device that has simply been powered off is indistinguishable from "
        "one that has been removed or has failed. ICMP may also be filtered by "
        "the device's own firewall."
    )

    OFFLINE_AFTER_S = 1800
    LATENCY_THRESHOLD_MS = 200

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []

        # Only alert on devices marked trusted -- those are the ones whose
        # absence is meaningful. A guest phone leaving is not an incident.
        rows = ctx.db.query(
            """SELECT * FROM devices
               WHERE trusted = 1 AND last_seen < ? AND last_seen > ?""",
            (ctx.now - self.OFFLINE_AFTER_S, ctx.now - 86400 * 7),
        )
        for row in rows:
            name = row["label"] or row["hostname"] or row["ip"] or row["device_id"]
            mins = int((ctx.now - row["last_seen"]) / 60)
            findings.append(
                Finding(
                    dedup_key=f"offline:{row['device_id']}:{int(row['last_seen'])}",
                    severity=self.severity,
                    title=f"{name} has been unreachable for {mins} minutes",
                    description=(
                        f"{name} ({row['ip'] or 'no IP'}) was last seen "
                        f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(row['last_seen']))}.\n\n"
                        "BENIGN EXPLANATION: powered off, out of Wi-Fi range, or "
                        "asleep.\n\n"
                        "NEXT STEP: if this device should always be online, check "
                        "its power and network connection."
                    ),
                    device_id=row["device_id"],
                    evidence={"last_seen": row["last_seen"], "ip": row["ip"]},
                )
            )

        # Sustained latency to the gateway: the closest thing to a WAN health
        # signal available without SNMP.
        gw_rows = ctx.db.query(
            """SELECT AVG(rtt_ms) AS avg_rtt, COUNT(*) AS n
               FROM availability a JOIN devices d ON d.device_id = a.device_id
               WHERE a.ts >= ? AND a.reachable = 1 AND a.rtt_ms IS NOT NULL
                 AND d.ip = (SELECT value FROM meta WHERE key = 'gateway_ip')""",
            (ctx.now - 900,),
        )
        if gw_rows and gw_rows[0]["n"] and gw_rows[0]["n"] >= 5:
            avg = gw_rows[0]["avg_rtt"]
            if avg and avg > self.LATENCY_THRESHOLD_MS:
                findings.append(
                    Finding(
                        dedup_key=f"latency:gateway:{int(ctx.now // 3600)}",
                        severity="low",
                        title=f"Elevated gateway latency: {avg:.0f} ms average",
                        description=(
                            f"Average round-trip time to the gateway over the last "
                            f"15 minutes was {avg:.0f} ms, above the "
                            f"{self.LATENCY_THRESHOLD_MS} ms threshold.\n\n"
                            "BENIGN EXPLANATION: local congestion, someone "
                            "streaming or backing up, or Wi-Fi interference.\n\n"
                            "WORTH NOTING: sustained latency to the gateway can "
                            "also indicate an adversary-in-the-middle, since "
                            "traffic being relayed through another host takes a "
                            "longer path. Correlate with any ARP alerts."
                        ),
                        evidence={"avg_rtt_ms": round(avg, 1), "samples": gw_rows[0]["n"]},
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# 6. Behaviour outside the device class baseline
# ---------------------------------------------------------------------------
class ProfileDeviationDetection(Detection):
    rule_id = "profile_deviation"
    name = "Device is offering a service outside its class baseline"
    severity = "high"
    mitre_id = "T1046"
    mitre_name = "Network Service Discovery"
    blind_spots = (
        "Depends on correct device classification. A misclassified device is "
        "judged against the wrong baseline, which is why classification "
        "confidence is carried into the alert and low-confidence classes only "
        "apply the universal forbidden set."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        from ..profiles import BASELINES, DeviceClass, evaluate_port

        findings: list[Finding] = []
        rows = ctx.db.query(
            """SELECT p.port, p.proto, p.service, p.product, p.first_seen,
                      d.device_id, d.device_class, d.class_confidence,
                      d.hostname, d.label, d.ip, d.mac, d.class_signals
               FROM ports p JOIN devices d ON d.device_id = p.device_id
               WHERE p.closed_at IS NULL AND d.device_class IS NOT NULL"""
        )

        for row in rows:
            try:
                cls = DeviceClass(row["device_class"])
            except ValueError:
                continue

            verdict, explanation = evaluate_port(cls, row["port"])
            if verdict in ("expected", "tolerated"):
                continue

            baseline = BASELINES[cls]
            name = row["label"] or row["hostname"] or row["ip"] or row["device_id"]

            if verdict == "forbidden":
                severity = "critical" if cls in (
                    DeviceClass.PHONE, DeviceClass.CAMERA, DeviceClass.IOT_SENSOR
                ) else "high"
            else:
                severity = "medium"

            # A guess about the device class must not drive a confident alert.
            if row["class_confidence"] == "low":
                severity = downgrade(severity, 1)
            elif row["class_confidence"] == "medium":
                severity = downgrade(severity, 0)

            try:
                signals = json.loads(row["class_signals"] or "[]")
            except (TypeError, ValueError):
                signals = []

            findings.append(
                Finding(
                    dedup_key=f"profile:{row['device_id']}:{row['port']}",
                    severity=severity,
                    title=(
                        f"{name} ({baseline.label}) is offering "
                        f"{row['port']}/{row['proto']}"
                        + (f" -- {row['service']}" if row["service"] else "")
                    ),
                    description=(
                        f"PNMA classified this device as a "
                        f"{baseline.label.lower()} "
                        f"({row['class_confidence']} confidence) and it is "
                        f"listening on a port outside that profile.\n\n"
                        f"  Device    {name} ({row['ip'] or 'no IP'})\n"
                        f"  Class     {baseline.label}\n"
                        f"  Port      {row['port']}/{row['proto']}"
                        + (f" ({row['service']})" if row["service"] else "")
                        + f"\n  Verdict   {verdict.upper()}\n\n"
                        f"WHY THIS MATTERS HERE: {explanation}\n\n"
                        f"CLASS CONTEXT: {baseline.notes}\n\n"
                        "HOW THIS DEVICE WAS CLASSIFIED:\n"
                        + "".join(f"  - {s}\n" for s in signals[:5])
                        + "\nBENIGN EXPLANATION: the device was misclassified, "
                        "or you deliberately enabled this service.\n\n"
                        "NEXT STEP: if the class is wrong, naming the device in "
                        "the dashboard improves classification. If the class is "
                        "right, this service should not be there -- investigate "
                        "before simply closing the port."
                    ),
                    device_id=row["device_id"],
                    evidence={
                        "port": row["port"],
                        "device_class": cls.value,
                        "class_confidence": row["class_confidence"],
                        "verdict": verdict,
                        "explanation": explanation,
                        "service": row["service"],
                    },
                    correlation_key=f"port:{row['device_id']}:{row['port']}",
                    triggers_triage_scan=(verdict == "forbidden"),
                )
            )
        return findings


def default_rules() -> list[Detection]:
    """Every rule this build runs, network and host.

    The host rules are in the default set rather than behind a flag because an
    agent that reports on other people's devices while exempting the machine it
    runs on is reporting from an unexamined vantage point. They are safe on a
    host that has never collected: `host_facts` is simply empty and all three
    return nothing.

    Note they do not consult `ctx.in_learning_mode`, and should not. The
    learning window exists so a fresh install does not alert on every device it
    has just met for the first time; host posture debt is equally true on the
    first run as on the hundredth, and suppressing it for an hour would hide it
    during precisely the hour someone is watching the dashboard.
    """
    return [
        NewDeviceDetection(),
        ArpSpoofDetection(),
        ServiceDriftDetection(),
        C2IndicatorDetection(),
        ProfileDeviationDetection(),
        AvailabilityDetection(),
    ] + host_rules() + identity_rules()
