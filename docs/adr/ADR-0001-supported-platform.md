# ADR-0001: Supported platform

Status: Accepted

## Context

The first release needs one reproducible hardware and firmware tuple. Broader platform support would weaken compatibility evidence and recovery guarantees.

## Decision

OpenWrt 25.12.5, mediatek/filogic, glinet_gl-mt6000, aarch64_cortex-a53 and kernel 6.12.94 are the only first-release target tuple. Stock GL.iNet and upstream OpenWrt are separate recovery profiles.

## Consequences

Release artifacts and hardware qualification are limited to the accepted tuple. Other images and profiles remain recovery inputs rather than production targets.

## Verification

Exact image, SDK, revision and vermagic appear in the lock and compatibility report.
