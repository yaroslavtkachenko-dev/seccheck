# Changelog

## 1.1.0 (unreleased)

Windows version, `seccheck.ps1`, with `seccheck.cmd` to run it from anywhere.

- Same flags, JSON and exit codes as on macOS; the JSON adds `"platform":"windows"`. No admin rights, Windows PowerShell 5.1.
- Network: route, network profile, DNS, IPv6, exit point (ASN, then RDAP), LAN gateway.
- Open ports are judged against the firewall rules: a listener is a problem only when the network can reach it, and a warning while the firewall blocks it. The rules of Store apps and of Wi-Fi Direct are left out, since they apply only inside their own app or adapter.
- Known risky ports (SMB, Remote Desktop, WinRM, Jupyter, Node inspector, Docker API, databases, Ollama, LM Studio, ComfyUI, Gradio, dev servers) name the service, the risk and the fix, and stay a warning even when allowlisted. A port is named only when its process fits. Python's `http.server` is recognised by its command line.
- Rows that are not clean show the PID, how long the port has been listening and the command line, with anything that looks like a secret cut out.
- Device: BitLocker, antivirus, firewall per profile, Secure Boot, UAC, SMBv1, Remote Desktop, Windows Update, disk space.
- AI agents: Claude Code bypass mode and deny rules, Codex sandbox and approvals, plaintext tokens and unpinned `npx` packages in MCP configs (Claude Code, Claude Desktop, Cursor, Codex), Ollama's `OLLAMA_HOST`. A token is reported by kind and file, never by value.
- Background agent through Task Scheduler, without a console window; notifications are Windows toasts.
- Offline tests, `tests/run.ps1`, and a Windows job in CI.

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
