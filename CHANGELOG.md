# Changelog

## 1.0.0

First public release.

- Checks: tunnel route, DNS binding, IPv6 leak, exit point, LAN gateway, TCP listeners against an allowlist, FileVault, SIP, Gatekeeper, firewall, stealth mode, disk space, Time Machine encryption.
- Exit point is verified by ASN name and, when that does not match, by the registry (RDAP) record of the address block.
- Notifications on a change in the set of problems only. A problem is identified by a stable key, so a rotating exit address or a changing disk percentage does not re-notify.
- Background LaunchAgent: `--install-agent`, `--uninstall-agent`.
- `--json`, `--quiet`, `--no-net`, `--notify`, `--init-config`, `--version`.
- `VPN_EXPECTED=0` for machines without a VPN.
- English and Ukrainian output.
- Config, state and log live in the home directory, not next to the script.
