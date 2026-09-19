# Disclaimer, scope, and rules of use

PNMA is a personal network and host monitoring agent. It discovers devices on a
network you administer, inventories the services they expose, records their
availability, and audits the security posture of the machine it runs on.

Read this before you run it on any network, and before you run it on a network
other people also use.

---

## 1. What this software is not

- **It is not a penetration testing tool, and it is not an attack tool.** It has
  no exploitation capability, no credential handling, no lateral movement, and
  no payload delivery. It observes and reports.
- **It is not an IDS or an EDR.** It sees what devices *listen on*, not what they
  *send*. It has no traffic inspection, no signature matching, no behavioural
  detection on other hosts, and no ability to block anything.
- **It is not a compliance product.** Nothing it outputs is an audit, a
  certification, or evidence of compliance with any standard.
- **It is not a substitute for professional advice** on securing a network.

## 2. Authorised use only

**Run this only against a network you own or are explicitly authorised to
administer.**

Active discovery and port scanning generate traffic directed at other people's
devices. Depending on where you live, doing that to a network you do not control
may be a criminal offence — in the UK under the Computer Misuse Act 1990, in the
US under the Computer Fraud and Abuse Act, and under equivalent law elsewhere.
"I was only scanning" is not a defence, and neither is "it is my flat".

Specifically, do not run it against:

- a landlord's, employer's, university's, or neighbour's network;
- shared accommodation infrastructure you do not administer;
- hotel, café, airport, or any other public or guest network;
- a corporate network, including your own employer's, without written
  authorisation from whoever owns it.

The software enforces this as far as software can. It cannot know whether you
are authorised — only whether you are on the network you *said* you were.

## 3. The scope guard, and what it does and does not guarantee

PNMA pins itself to one network, declared in `config/pnma.toml`:

```toml
[network]
cidr        = "192.168.0.0/24"   # the ONLY range that may be touched
gateway_ip  = "192.168.0.1"
gateway_mac = "aa:bb:cc:dd:ee:ff"

[guard]
enforce_gateway_mac  = true       # refuse to run if the gateway is not this one
allow_unknown_network = false
```

- Every packet-emitting operation is authorised against `cidr` first.
- Every address returned by discovery is **re-authorised before it is recorded or
  scanned**, because discovery output is untrusted — a host can claim any address
  it likes in a reply.
- The gateway MAC is checked at startup and re-checked periodically. If you carry
  the laptop to a different network, the guard denies and active probing stops.
- Ranges in `exclude_cidrs` are never touched, which is how VPN and hypervisor
  virtual adapters are kept out.
- Every scan is written to the `scan_runs` table with its target. `pnma audit`
  prints that record. **If it is not in the audit trail, it did not happen.**

**What the guard cannot do:** it cannot tell whether you are authorised to
monitor the network it is pinned to. Configuring the guard is you asserting
authorisation, not the software verifying it.

## 4. Other people on your network

This is the part most tools skip.

If anyone else uses your network — family, housemates, guests — monitoring it
collects information about them: which devices they own, when those devices are
present, and what services those devices run. Device presence is a proxy for
whether a person is home.

PNMA is built to limit that as much as a monitoring tool can:

- **Passive capture is restricted at the kernel** to a BPF filter of
  `arp or (udp and (port 67 or port 68))`. Browsing traffic, DNS queries, and
  payloads of any kind never reach userspace. This is a technical constraint,
  not a promise in a privacy policy.
- **Port scanning is polite by default** (`-T2`, top 100 ports, no version
  probes) because aggressive scanning crashes IoT devices and printers.
- **No content is ever inspected.** The agent records that a device exists, what
  it listens on, and whether it responds.

None of that is consent. **Tell the people who share your network that you are
running this, what it records, and how long it keeps it** (`retention_days`,
default 30). If someone objects, exclude their device with `exclude_ips` or do
not run it. A monitoring tool operated in secret against the people you live
with is a surveillance tool regardless of how narrow its BPF filter is.

## 5. Data handling

- **Everything stays local.** The database is a SQLite file on your machine.
  There is no cloud component, no telemetry, no analytics, and no phone-home.
- **The dashboard binds to `127.0.0.1` by default** and should stay that way. It
  is unauthenticated. Exposing it to the LAN publishes a complete reconnaissance
  report of your network to everyone on that network.
- **Outbound alerting is off by default** and must be enabled deliberately.
- **API keys** are stored in the OS credential store (DPAPI, Keychain, Secret
  Service) rather than in config files.
- **The database identifies your household.** MAC addresses, hostnames, and
  device labels are personal data. Do not commit it, paste it into an issue, or
  attach it to a bug report. `data/` is gitignored for that reason.
- **Every published screenshot and figure comes from `pnma seed`**, which
  generates a synthetic network and a synthetic host. No real MAC, hostname, or
  SSID appears in any documentation for this project.

## 6. Accuracy, and the limits of what it can see

PNMA reports three states, not two: `ok`, `finding`, and **`unknown`**.
`unknown` means *the check could not run* — usually because the collector was
not elevated. It is never rendered as passing. This matters because the failure
mode it guards against is real: some Windows queries return a message that
*looks* like a clean result when the true answer is "access denied".

Known blind spots, stated rather than implied:

- Per-device traffic volume and destinations. A host on a switched network does
  not receive other devices' traffic.
- Outbound C2 beaconing and data exfiltration, for the same reason.
- UDP services — only TCP ports are scanned.
- Devices that never respond and never appear in a discovery sweep.
- Without a packet capture driver, devices using randomised MAC addresses cannot
  be tracked across address rotation.

`pnma detections` lists every rule and its individual blind spots.

**A quiet dashboard is not evidence of a secure network.** It is evidence that
nothing matched the rules that ran.

## 7. No warranty

This software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and noninfringement. In no event shall the authors be
liable for any claim, damages, or other liability arising from the use of this
software.

Scanning can disrupt devices. Embedded and IoT hardware in particular is known
to hang, reboot, or emit garbage when scanned, which is why the defaults are
conservative. **You are responsible for what you point this at.**

## 8. Summary

| | |
|---|---|
| Run it on | a network you own or administer |
| Never run it on | anyone else's network, or any public network |
| It collects | device identity, open ports, availability, local host posture |
| It never collects | traffic content, DNS queries, browsing activity, payloads |
| Data goes | nowhere — local SQLite only |
| Dashboard | localhost, unauthenticated, keep it that way |
| Other people on your network | tell them |
