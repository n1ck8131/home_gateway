# P3 Windows client activation gate

This runbook is an offline-prepared field contract. It does not authorize an Amnezia import/connect/disconnect, Windows network change, SSH session, or server peer mutation.

## Inputs and hard stops

- Use only a protected runtime pin set. Never copy a host, address, public key, private-key path, profile field, or raw egress value into tracked files or evidence.
- Pin the exported profile SHA-256 and AmneziaVPN `5.0.1.5` file version, Authenticode signer result, and binary SHA-256.
- Pin the expected Guest peer fingerprint SHA-256 from the sanitized Gate 6.5 receipt and the expected self-hosted egress identity SHA-256 from protected runtime state.
- The protected runtime pins the local payload, remote payload/protocol identities, known-hosts file, three HTTPS authority hashes and current public `/32` hash. The client gate calls the same tracked launcher `ClientObserve` action through its fixed child boundary; it does not contain a second server observer.
- Stop if RedShield or Cisco baseline collection is incomplete, a self-hosted adapter already exists, any pin is stale, or a requested action would affect another profile/adapter.

## Ordered client gate

1. Run `p3-profile-stage.ps1 -Action Prepare` with exact driver/payload hashes. In the official UI, export exactly one new profile to the prepared `profile-export.conf` target. Do not import or connect yet.
2. Run `p3-profile-stage.ps1 -Action Verify`. It exclusively locks and hashes that export, performs pinned `hgctl tunnel inspect`, and installs the provider-neutral protected copy and pin. `Cleanup` may remove only marker-owned temporary metadata; it never deletes the export or installed profile.
3. At separately approved **Gate 6.6**, run production `p3-client-gate.ps1 -Action Preflight`. Production never accepts `ObservationPath`; that input is restricted to explicit `TestOnlyFixture` mode under an injected test root. Require current exact profile, client and known-hosts hashes, the Authenticode result, current RedShield/Cisco class hashes and counts, and zero self-hosted adapters. Write the protected PRE receipt for later equality checks.
4. Only after a separate live approval, import and connect the one new self-hosted profile through the official Amnezia UI.
5. Run production `PostConnect`. It collects current client, adapter, route and three-HTTPS state, generates one cryptographically random nonce and passes it through the tracked `p3-amnezia-peer-guard.ps1 -Action ClientObserve` launcher. Require exact payload/protocol and nonce hashes, selected Guest match, fresh handshake, expected before/after counter hashes, traffic delta and bounded observation duration, plus exactly one self-hosted adapter, route attribution and the protected egress identity hash.
6. On client anomaly, remove only the new local Amnezia client profile through the official UI. Preserve the server Guest peer until a separate server cleanup approval. Run production `PostRollback`; it collects current state and computes RedShield/Cisco equality from the protected PRE receipt itself. Require profile/adapter absence and exact equality.

All evidence is sanitized: schema/version, hashes, counts, freshness booleans, adapter-class hashes, and equality flags only. Never retain raw keys, epochs, addresses, routes, adapter names, DNS values, or profile contents.

## Distinct rollback boundaries

- Gate 6.5 server anomaly: identify exactly one candidate Admin/Guest from its gate-owned receipt. Before any peer creation, require a source-pinned AmneziaVPN `5.0.1.5` capability mapping and a read-only UI check proving the exact one-peer removal control exists. Otherwise stop. Roll back only that server peer through the official UI. A separately guarded exact-one-peer `awg syncconf` path is emergency-only.
- Gate 6.6 client anomaly: remove only the new local client profile; do not remove the server Guest in the same action.
- `Clear server from Amnezia software` is prohibited.

`PostRollback` requires a sanitized `profile_absent=true` observation and never hashes an expected-absent profile path. P3 is not terminal until the network `FullRestore` and the separately planned/approved, network-plan-bound `RestoreConfigAcl` both pass.

The remote helper stays installed but inert throughout P3. `AgentStop` is mandatory at every terminal success, failure, cancellation and rollback path. Gate 6.6 approval does not authorize Gate 7.2, adapter-loss recovery, reboot recovery, Gate 7.3, helper removal or emergency rollback; each remains separately candidate-bound.
