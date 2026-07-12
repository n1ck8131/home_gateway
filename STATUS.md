# Project Status

Current phase: P0 Foundation and Compatibility
Release level: planning-approved

## P0A Foundation

- State: blocked
- Missing evidence: clean Linux verification with `CAP_NET_ADMIN` and the network-lab prerequisites.

## P0B Compatibility

- State: blocked
- Missing evidence: clean OpenWrt 25.12.5 SDK build for the pinned AWG2 packages and userspace contingency measurements.

## External gates

- GL-MT6000 hardware smoke: not-run
- Router-to-VPS AWG2 handshake: P3 gate
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- Linux verification with `CAP_NET_ADMIN` has not run.
- The pinned AWG2 packages have not completed a clean OpenWrt 25.12.5 SDK build.
