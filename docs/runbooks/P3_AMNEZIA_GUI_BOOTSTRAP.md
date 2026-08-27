# P3 AmneziaVPN GUI bootstrap

This runbook is an operator-only gate. It does not authorize cloud creation, SSH, profile activation, or Windows network changes.

1. After the separately approved Droplet and SSH gates, install the pinned Windows AmneziaVPN 5.0.1.5 client through its supported **Self-hosted VPN** GUI flow.
2. Select **AmneziaWG only**. Do not select an additional transport and do not call internal Amnezia shell scripts: they are not a stable supported API.
3. After the separate guest-creation approval, use **Guest access** and export the guest in native AmneziaWG format directly to the approved protected local path. Do not paste its content into a terminal, ticket, or repository.
4. Removing the profile from the app is limited client-side rollback. **Clear server from Amnezia software** is a separate broad/destructive server action and always needs fresh approval; recovery is to rebuild a new server/profile through the approved GUI gates, never to reuse an old profile or automate an internal shell path.
5. Record only the observed immutable server image ID/digest after installation. The tagged client references `amneziavpn/amneziawg-go:latest`, so no pre-install digest is implied by this lock.
