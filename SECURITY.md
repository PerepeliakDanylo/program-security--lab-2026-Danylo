# Security Policy — RDR2 Dynamic Reload

## Supported versions

| Component | Supported | Where it is published |
|---|---|---|
| `DynamicReloadSpeed.asi` (mod) | latest **1.2.x** only (currently 1.2.2) | NexusMods page of Dynamic Reload Speed (author RedziYT) — the only canonical source |
| Maintainer tools (`tools/drs_release`, `tools/drs_hub`) | latest **1.0.x** | GitHub Releases of this repository, tags `tools-v<version>` |
| Older versions | not supported — please update | — |

Game build tested: RDR2 PC `1.0.1491.50`. Later builds are handled on a best-effort basis: the plugin
re-discovers its targets at every start and stays inactive (game untouched) when it cannot confirm them.

## Reporting a vulnerability

Please **do not** post exploit details in public comments or issues.

1. Preferred: GitHub → this repository → **Security** → **Report a vulnerability** (private advisory).
2. Alternative for players: a private message to **RedziYT** on NexusMods.

Include: the component and version, what an attacker can do, steps to reproduce, and logs **without**
personal data (`DynamicReloadSpeed.log` contains no folder paths; remove user names from anything else).

## What happens next

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| Assessment (severity, affected versions) | within 14 days |
| Fix released for critical / high issues | within 30 days (PATCH release) |
| Public note | in the mod changelog / release notes after the fix is available |

Out of scope: Red Dead Redemption 2 itself, Rockstar services, other mods, ScriptHookRDR2.
Red Dead Online is not supported — remove the plugin before going online.
