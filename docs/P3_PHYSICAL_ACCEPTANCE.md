# P3 physical acceptance

This runbook is for the operator who controls the GL-MT6000, its wired
recovery path and the VPS provider account. Repository tests and QEMU do not
replace this procedure.

## Current boundary

`preflight-p3.ps1` is read-only. It verifies the approved target tuple, strict
SSH host-key use, recovery attestations, WAN route invariants and either the
absence of the tunnel or one fresh handshake to the approved endpoint. Its
JSON evidence is redacted and commits to the exact validated inventory,
known-hosts file and preflight script with SHA-256 values.

`smoke-awg2.ps1` is read-only unless `-ConfirmInstall` is present. With that
switch it temporarily installs the two AWG2 packages, tests the kernel UAPI
and removes all nonce-owned temporary state. The `routerd` APK in the same
build directory is hash-verified but is never copied by this smoke.

Neither script proves selective egress, DNS/IPv6/QUIC behavior, MTU,
AWG-down isolation, reboot persistence, package lifecycle on the physical
router or resource/throughput targets. P3.5 remains open until those results
exist for one real router and one real VPS.

## Prerequisites

Do not begin a mutating step until all items are true:

- GL-MT6000 is behind the existing ISP router/ONT, not the primary WAN.
- A wired management client can still reach the router if the tunnel fails.
- The pinned factory image has been downloaded and its lock-file SHA-256 has
  been verified.
- The VPS provider console and recovery account have been tested.
- Router and VPS SSH host keys were verified through an independent channel.
- Real endpoint, tunnel ranges and public keys are approved. Private keys and
  credentials remain outside Git.
- The clean SDK build produced the exact files and SHA-256 values recorded in
  `manifest/versions.lock.yaml`.

Copy the sanitized template into the ignored local file and replace every
example value:

```powershell
Copy-Item .\deploy\openwrt\p3-acceptance.example.json .\p3-acceptance.local.json
```

Set `sanitized_example` to `false`. Set a recovery flag to `true` only after
performing that recovery check. Populate `known_hosts.local` only with a host
key whose fingerprint was independently verified; an unverified
`ssh-keyscan` result is not a trust decision.

## 1. Dry run

The dry run parses and validates the inventory without resolving SSH or
creating evidence:

```powershell
.\scripts\openwrt\preflight-p3.ps1 `
  -InventoryFile .\p3-acceptance.local.json `
  -KnownHostsFile .\known_hosts.local `
  -EvidenceDirectory .\artifacts\p3-read-only `
  -WhatIf
```

Expected terminal marker: `WHATIF P3 read-only preflight`.

## 2. Read-only router preflight

Use a new or empty evidence directory:

```powershell
.\scripts\openwrt\preflight-p3.ps1 `
  -InventoryFile .\p3-acceptance.local.json `
  -KnownHostsFile .\known_hosts.local `
  -EvidenceDirectory .\artifacts\p3-read-only
```

Expected marker: `P3_READ_ONLY_PREFLIGHT_PASS`. Preserve
`p3-read-only-preflight.json`. It contains a target hash and validated facts,
not hostnames, endpoints or peer material. Its commitment hashes let a reviewer
match the PASS to the separately retained approved inputs and tool version.

For the clean pre-install check, set `tunnel.expected_up` to `false`; an
existing interface is rejected. After an approved deployment, set it to
`true`; the preflight then requires exactly one fresh handshake and the
approved endpoint while retaining the WAN endpoint route.

## 3. Temporary exact-kernel AWG2 smoke

Run the non-mutating previews first. `PackageDirectory` may contain the two
AWG2 APKs alone or those files plus the exact hash-pinned `routerd` APK.

```powershell
.\scripts\openwrt\smoke-awg2.ps1 `
  -RouterHost <approved-router-host> `
  -PackageDirectory .\artifacts\openwrt-run2 `
  -KnownHostsFile .\known_hosts.local `
  -WhatIf

.\scripts\openwrt\smoke-awg2.ps1 `
  -RouterHost <approved-router-host> `
  -PackageDirectory .\artifacts\openwrt-run2 `
  -KnownHostsFile .\known_hosts.local
```

The second command must end with `AWG2_PREFLIGHT_PASS` and makes no remote
changes. The following invocation is an explicit request for temporary remote
mutation:

```powershell
.\scripts\openwrt\smoke-awg2.ps1 `
  -RouterHost <approved-router-host> `
  -PackageDirectory .\artifacts\openwrt-run2 `
  -KnownHostsFile .\known_hosts.local `
  -ConfirmInstall
```

Keep the printed recovery token until `AWG2_HARDWARE_SMOKE_PASS` is recorded.
If cleanup cannot be confirmed, stop and run only the ownership-checked
recovery command printed by the script. Do not continue to persistent package
installation.

## 4. Remaining P3.5 evidence

After an approved persistent deployment, collect all of the following before
changing the primary WAN:

- exact `routerd` install, r1-to-r2 upgrade and remove with UCI/LKG hashes;
- service boot ordering, restart and reboot/LKG reconciliation;
- ordinary site through WAN and selected site through VPS egress;
- router DNS with A, AAAA and CNAME set population and no IPv6 leak;
- TCP, UDP and QUIC policy behavior plus measured working MTU;
- AWG-down packet capture proving VPN-class fail-closed behavior;
- wired Ethernet recovery after tunnel, service and reboot faults;
- CPU, RAM, flash and throughput measurements;
- VPS restricted SSH, non-public control plane and provider-console recovery.

Record command output, timestamps and captures in a new ignored evidence
directory. Never store private keys, tokens, passwords, raw peer configs or
unredacted support bundles in the repository.

The exit gate is one complete router/VPS evidence bundle reviewed against
`docs/ACCEPTANCE_MATRIX.md`. A successful preflight or temporary module smoke
alone must not be reported as `single-site core-ready`.
