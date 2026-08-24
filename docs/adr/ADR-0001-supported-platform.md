# ADR-0001: Supported platform

Status: Accepted

## Context

The project needs an early production target that can prove policy and recovery behavior before purchasing router hardware, followed by one reproducible final hardware and firmware tuple. Broader platform support would weaken compatibility evidence and recovery guarantees.

## Decision

The current Windows PC is the first production target for P3-P11. OpenWrt 25.12.5, mediatek/filogic, glinet_gl-mt6000, aarch64_cortex-a53 and kernel 6.12.94 are the final P12 router tuple. Stock GL.iNet and upstream OpenWrt are separate recovery profiles.

## Consequences

Windows and router releases have independent platform adapters and recovery profiles under the same policy contracts. Router hardware qualification is limited to the accepted tuple. Other images and profiles remain recovery inputs rather than production targets.

## Verification

P3-P11 repeat the safety matrix on Windows. P12 verifies the exact image, SDK, revision and vermagic from the lock and compatibility report on Flint 2.
