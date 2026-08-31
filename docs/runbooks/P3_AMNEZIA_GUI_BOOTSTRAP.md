# P3 AmneziaVPN GUI bootstrap

This runbook is an operator-only gate. It does not authorize cloud creation, SSH, profile activation, or Windows network changes.

The protected profile staging, sanitized Windows observation schema and distinct server/client rollback workflow are defined in [P3_WINDOWS_CLIENT_ACTIVATION.md](P3_WINDOWS_CLIENT_ACTIVATION.md). Before peer creation, require a source-pinned AmneziaVPN `5.0.1.5` capability mapping and a read-only UI check proving the exact one-peer removal control exists; otherwise stop before creation.

## Separately approved future gates

Task 6A is offline evidence only. It grants no authority to execute any gate below, and no later gate inherits approval from an earlier one.

1. **Read-only prerequisite observation (before Gate 6.4L):** after its own exact hash/challenge approval, use `p3-prelive-prerequisite.ps1` for the prerequisite-scoped agent and transient observer batch plus three controller HTTPS observations. Assemble and validate one protected prerequisite receipt; `AgentStop` is mandatory in `finally`, and teardown failure is terminal. This approval does not authorize runtime preparation or helper installation.
2. **Gate 6.4L:** only after the prerequisite receipt is independently accepted, form `PreparePlan` and prepare the protected runtime that binds that immutable receipt and the canonical 27-field server baseline. Start no standalone or persistent operator-owned session.
3. **Gate 6.4R-pre:** invoke `p3-remote-helper.ps1` `RemoteInstallPlan` inside its own short-lived protected agent batch. Execute no install and no server mutation.
4. **Gate 6.4P:** after its own exact approval, invoke `RemoteInstall` to install one exact inert helper at `/usr/local/libexec/home-gateway-p3-peer-guard`.
5. **Gate 6.4R-post:** attest the helper and reconcile the exact `amnezia-awg2` container, `/opt/amnezia/awg/awg0.conf`, `/opt/amnezia/awg/clientsTable`, `awg0`, image, listeners, host policy, ingress, peer set and zero leftovers.
6. **Gate 6.5A:** after a separate candidate approval, perform exactly one source-pinned full-access management GUI action. `clientName` is mutable display metadata; acceptance requires the protected management operation-context receipt.
7. **Gate 6.5B:** after a separate candidate approval, perform exactly one Guest GUI action and export one native profile directly to its protected destination. Guest identity requires the protected inspector's X25519 public fingerprint receipt; never display or retain profile/key contents.
   Use `ManagementReceiptPlan` -> `ManagementReceiptRecord` -> `ManagementReceiptConsume` or `GuestProfilePlan` -> `GuestProfileInspect` -> `GuestProfileConsume` on the existing guard launcher. Each plan binds its protected evidence root, immutable candidate/nonce/pre-post/runtime identities and pinned local executable/profile facts. Record/inspect requires the exact plan hash and challenge; consume is atomic and single-use. Management remains explicitly owner-observed and non-cryptographic. Guest inspection uses pinned `hgctl tunnel inspect`, persists only the derived X25519 public fingerprint, and requires it to equal the candidate fingerprint.
8. **Gate 6.6:** after a separate candidate approval, import and connect only that exact profile, then run the nonce-bound client observation.
9. **Gate 7.2, adapter-loss recovery, reboot recovery and Gate 7.3** remain separately planned, candidate-bound and approved operations.
10. **Emergency rollback** is a separate exact candidate only. It may remove only the candidate bound in its receipt and cannot substitute for the supported official-UI rollback.

Use the pinned Windows AmneziaVPN `5.0.1.5` **Self-hosted VPN** GUI flow with **AmneziaWG only**. Do not call internal Amnezia shell scripts as a stable API. The accepted terminal topology is exactly the preserved baseline Admin, one `homegateway` management Admin and one static PC Guest; any other delta stops the gate. **Clear server from Amnezia software** remains prohibited without a new destructive-action approval.

There are exactly two documented executable launchers. The selected `p3-amnezia-peer-guard.ps1` action owns guard, client-observation, emergency terminal work and the protected management/Guest evidence actions above. The `p3-remote-helper.ps1` action switch owns `RemoteInstallPlan`, `RemoteInstall`, `RemoteRemovePlan` and `RemoteRemove`; each selected remote action runs in a separate short-lived batch. Actions that require SSH load the protected context, start and validate exactly one dedicated agent/session, execute only the selected action, then in `finally` perform receipt-bound teardown, wait for and re-observe the exact PID/socket disappearance, and remove only the matching protected receipt. Initial validation uses start-bound emergency teardown, and any cleanup failure is terminal even when the action body already failed or was cancelled. No standalone or persistent agent is an approved entrypoint. `AgentPlan` remains a read-only preparation action without a session; `RemoteInstallPlan` and `RemoteRemovePlan` are remotely read-only but still own and tear down a batch session.

Helper removal is not part of normal gate cleanup.
