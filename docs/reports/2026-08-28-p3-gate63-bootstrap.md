# P3 self-hosted Gate 6.1-6.3 field report

Date: 2026-08-28

Result: PASS for the bounded server-bootstrap scope through Gate 6.3. Gate 6.4 UDP publication and all client/profile/Windows-network gates remain not run.

## Executed boundary

- The owner created one DigitalOcean Basic Regular `$6/month` Droplet in `ams3` with Ubuntu 24.04 LTS x64, IPv6, monitoring and the dedicated SSH public key. The Cloud Firewall remained SSH-only and restricted to the freshly qualified management egress `/32`.
- The ED25519 host key was pinned before the first key-only SSH. Droplet identity, region, hostname, public-address metadata, uploaded-key count and operating-system metadata matched the owner-observed DigitalOcean resource.
- The official AmneziaVPN 5.0.1.5 GUI path installed only AmneziaWG. Read-only observation found exactly one running `amnezia-awg2` container, restart policy `always`, no health-check override, no published TCP port and one host-published UDP port `38556`. Docker was active and enabled.
- The observed immutable container identity was `sha256:a9b1cbbfa26aa509def4b037ed4fe817a05d6473e5dc0b065c31e7d4492a2c68` for both image ID and repository digest.
- A password-locked `homegateway` account with one dedicated authorized key and passwordless sudo was created without changing the root recovery key or SSH policy. A separate fresh key-only login proved UID `1000` and passwordless sudo before hardening.
- Stage 3 published the exact hardening drop-in atomically, validated `sshd`, performed `systemctl reload ssh` only, and proved a second fresh key-only `homegateway` login before the persistent recovery channel was committed and closed.

## Gate 6.3C acceptance evidence

| Evidence | Observed result |
|---|---|
| Hardening file SHA-256 | `9365efc20b34eefaaed732d5e5bcffbbca95837af65d339ab91374ce34473987` |
| Post-change SSH tree SHA-256 | `78b5f631511814d09e598519b4d3ef2c050fcf7fb1dd8fb15c9dc07dd249d362` |
| `sshd` candidate validation | `YES` |
| Effective root login | `NO` |
| Effective root/user password authentication | `NO` |
| Effective `homegateway` public-key authentication | `YES` |
| SSH service | active; enabled state `disabled` |
| Service operation | reload only; no restart and no reboot |
| Fresh key-only login and passwordless sudo proof | `YES` |
| Direct apply/verify completion | `GATE63C_STAGE3_DIRECT_COMPLETE=YES` |
| Recovery commit | `GATE63C_RECOVERY_COMMIT=ACCEPTED` |
| Recovery SSH exit | `0` |

## Recovery transport incident and correction

The first recovery-shell bootstrap attempt was stopped before readiness because raw Base64 exceeded the Windows native-argument boundary and Windows PowerShell 5.1 quoting differed from PowerShell 7. The bootstrap payload has no top-level server mutation; rollback/reload commands were function definitions and were not invoked during that failed attempt.

The launcher transport was replaced with bounded gzip plus Base64, a conservative `<7800` command-length hard stop and `set -euo pipefail` before payload execution. A real harmless 7.6 KiB roundtrip and corrupted-payload rejection passed under Windows PowerShell 5.1 and PowerShell 7; the live command measured `2705` characters. Independent source-level security review returned GO before the successful retry.

## Preserved boundaries

- The DigitalOcean Cloud Firewall still exposes only SSH from the qualified management `/32`; UDP `38556` is observed but not cloud-published.
- No guest was created and no VPN profile, private key, password, token, raw configuration or protected client file is recorded here.
- No self-hosted Windows client profile was imported or activated. Self-hosted handshake, public egress, DNS/IPv6 leak, failure-mode, restart/recovery, exact Plan, Apply/Confirm and terminal `FullRestore` evidence remain open.
- RedShield, Cisco and Windows routing, DNS, firewall, adapters and services were not disconnected or reconfigured. No reboot was performed.
- Gate 6.4 requires fresh explicit approval for exactly UDP `38556` plus a Docker/host/Cloud Firewall union audit. SSH and that one UDP port must be the only public inbound services.
