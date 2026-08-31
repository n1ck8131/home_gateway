# P3 AmneziaVPN GUI bootstrap

This runbook is an operator-only gate. It does not authorize cloud creation, SSH, profile activation, or Windows network changes.

The protected profile staging, sanitized Windows observation schema and distinct server/client rollback workflow are defined in [P3_WINDOWS_CLIENT_ACTIVATION.md](P3_WINDOWS_CLIENT_ACTIVATION.md). Before peer creation, require a source-pinned AmneziaVPN `5.0.1.5` capability mapping and a read-only UI check proving the exact one-peer removal control exists; otherwise stop before creation.

## Separately approved future gates

Task 6A is offline evidence only. It grants no authority to execute any gate below, and no later gate inherits approval from an earlier one.

1. **Gate 6.4L:** prepare the protected runtime bundle and prove the read-only `AgentPlan`. Do not start a standalone operator-owned session. Stop on any manifest, ACL, toolchain, host-key, key-count or fingerprint mismatch.
2. **Gate 6.4R-pre:** form the read-only `RemoteInstallPlan`, then record separately owner-observed Cloud Firewall and current local-baseline receipts. Execute no install and no server mutation.
3. **Gate 6.4P:** after its own exact approval, install one exact helper at `/usr/local/libexec/home-gateway-p3-peer-guard`. The helper is inert when not invoked and remains installed through P3 so every later observation uses the same attested payload.
4. **Gate 6.4R-post:** attest the installed helper and run the server and combined reconciliation. Require the exact container, image, listener, host policy, public ingress, baseline peer set, zero leftovers, payload and protocol identities.
5. **Gate 6.5A:** after a separate candidate approval, arm the Admin guard and perform exactly one Admin GUI action. Preserve the pre-existing baseline peer and accept only the candidate-bound exact-plus-one transition.
6. **Gate 6.5B:** after a separate candidate approval, arm the Guest guard, perform exactly one Guest GUI action and export exactly one native AmneziaWG profile directly to its protected destination. Never display or retain its contents.
7. **Gate 6.6:** after a separate candidate approval, import and connect only that exact profile, then run the nonce-bound client observation described in the Windows activation runbook.
8. **Gate 7.2, adapter-loss recovery, reboot recovery and Gate 7.3** remain separately planned, candidate-bound and approved operations. None is authorized by success at Gate 6.6.
9. **Emergency rollback** is a separate exact candidate only. It may remove only the candidate bound in its receipt and cannot substitute for the supported official-UI rollback.

Use the pinned Windows AmneziaVPN `5.0.1.5` **Self-hosted VPN** GUI flow with **AmneziaWG only**. Do not call internal Amnezia shell scripts as a stable API. The accepted terminal topology is exactly the preserved baseline Admin, one `homegateway` management Admin and one static PC Guest; any other delta stops the gate. **Clear server from Amnezia software** remains prohibited without a new destructive-action approval.

The selected `p3-amnezia-peer-guard.ps1` action is the only documented executable entrypoint for guard, client-observation and emergency terminal work. That launcher owns one complete batch: it loads the protected context, starts and validates exactly one dedicated agent/session, executes the selected action, then in `finally` performs receipt-bound `AgentStop`, waits for and re-observes the exact PID/socket disappearance, and removes only the protected receipt. A cleanup failure is terminal even when the action body already failed or was cancelled. `AgentPlan` and `RemoteInstallPlan` remain read-only preparation actions and do not create a session.

Helper removal is not part of normal gate cleanup.
