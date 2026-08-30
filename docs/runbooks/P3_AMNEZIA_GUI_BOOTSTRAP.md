# P3 AmneziaVPN GUI bootstrap

This runbook is an operator-only gate. It does not authorize cloud creation, SSH, profile activation, or Windows network changes.

The protected profile staging, sanitized Windows observation schema and distinct server/client rollback workflow are defined in [P3_WINDOWS_CLIENT_ACTIVATION.md](P3_WINDOWS_CLIENT_ACTIVATION.md). Before peer creation, require a source-pinned AmneziaVPN `5.0.1.5` capability mapping and a read-only UI check proving the exact one-peer removal control exists; otherwise stop before creation.

1. Before any peer action, perform a bounded read-only reconciliation of the expected container, Docker/host/Cloud Firewall public ingress union and baseline peer-set identity. Stop on any mismatch.
2. Use the pinned Windows AmneziaVPN 5.0.1.5 client through its supported **Self-hosted VPN** GUI flow and select **AmneziaWG only**. Do not call internal Amnezia shell scripts as a stable API.
3. Preserve the pre-existing baseline Admin peer unchanged. After a separate exact approval, add exactly one `homegateway` management Admin peer. Accept only the exact candidate delta and retain a candidate-specific rollback receipt.
4. Supported Admin rollback removes only that exact peer through the official Amnezia UI. The reviewed candidate-bound direct rollback is emergency-only and requires its own exact guard and approval.
5. After the separate Guest-creation approval, add exactly one static PC Guest through **Guest access** and export it in native AmneziaWG format directly to the approved protected local path. Do not paste its content into a terminal, ticket, or repository.
6. The accepted terminal topology is exactly the preserved baseline Admin, one `homegateway` management Admin and one static PC Guest. Any other delta stops the gate.
7. Removing the local profile from the app is client-only rollback and must preserve the server Guest. Guest removal is a separate server mutation. **Clear server from Amnezia software** is a broad/destructive action requiring fresh approval.
8. Record only the observed immutable server image identity after installation. The tagged client references `amneziavpn/amneziawg-go:latest`, so no pre-install digest is implied by this lock.
