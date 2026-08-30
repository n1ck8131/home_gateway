# P3 Windows client activation gate

This runbook is an offline-prepared field contract. It does not authorize an Amnezia import/connect/disconnect, Windows network change, SSH session, or server peer mutation.

## Inputs and hard stops

- Use only a protected runtime pin set. Never copy a host, address, public key, private-key path, profile field, or raw egress value into tracked files or evidence.
- Pin the exported profile SHA-256 and AmneziaVPN `5.0.1.5` file version, Authenticode signer result, and binary SHA-256.
- Pin the expected Guest peer fingerprint SHA-256 from the sanitized Gate 6.5 receipt and the expected self-hosted egress identity SHA-256 from protected runtime state.
- The runtime Gate 6.5 guard pins the local payload, remote payload/protocol identities, known-hosts file and current public `/32`. It requires three bounded HTTPS observations to agree before bounded SSH, and accepts only a bounded attestation matching both remote identities before printing `READY_FOR_UI=YES`.
- Stop if RedShield or Cisco baseline collection is incomplete, a self-hosted adapter already exists, any pin is stale, or a requested action would affect another profile/adapter.

## Ordered client gate

1. Run `p3-profile-stage.ps1 -Action Prepare` with exact driver/payload hashes. In the official UI, export exactly one new profile to the prepared `profile-export.conf` target. Do not import or connect yet.
2. Run `p3-profile-stage.ps1 -Action Verify`. It exclusively locks and hashes that export, performs pinned `hgctl tunnel inspect`, and installs the provider-neutral protected copy and pin. `Cleanup` may remove only marker-owned temporary metadata; it never deletes the export or installed profile.
3. Run `p3-client-gate.ps1 -Action Preflight` against a bounded observation record. Require mandatory exact profile, client and known-hosts hashes plus the signature, RedShield/Cisco class snapshots, and zero self-hosted adapters.
4. Only after a separate live approval, import and connect the one new self-hosted profile through the official Amnezia UI.
5. Run `PostConnect`. Require exactly one self-hosted adapter; route attribution to that adapter; selected Guest fingerprint match; fresh handshake and RX/TX delta; and three agreeing HTTPS observations matching the protected egress identity hash.
6. On client anomaly, remove only the new local Amnezia client profile through the official UI. Preserve the server Guest peer until a separate server cleanup approval. Run `PostRollback` and require profile/adapter absence plus RedShield/Cisco equality to PRE.

All evidence is sanitized: schema/version, hashes, counts, freshness booleans, adapter-class hashes, and equality flags only. Never retain raw keys, epochs, addresses, routes, adapter names, DNS values, or profile contents.

## Distinct rollback boundaries

- Gate 6.5 server anomaly: identify exactly one candidate Admin/Guest from its gate-owned receipt. Before any peer creation, require a source-pinned AmneziaVPN `5.0.1.5` capability mapping and a read-only UI check proving the exact one-peer removal control exists. Otherwise stop. Roll back only that server peer through the official UI. A separately guarded exact-one-peer `awg syncconf` path is emergency-only.
- Gate 6.6 client anomaly: remove only the new local client profile; do not remove the server Guest in the same action.
- `Clear server from Amnezia software` is prohibited.

`PostRollback` requires a sanitized `profile_absent=true` observation and never hashes an expected-absent profile path. P3 is not terminal until the network `FullRestore` and the separately planned/approved, network-plan-bound `RestoreConfigAcl` both pass.
