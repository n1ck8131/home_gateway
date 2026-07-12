# ADR-0008: Cisco discovery

Status: Accepted

## Context

Cisco Secure Client owns workstation networking state that the gateway may observe but must not modify or bypass.

## Decision

cisco-discovery is read-only, uses a scoped token and offline queue, and never bypasses Cisco policy. work-pc is one logical device with Ethernet and Flint Wi-Fi identities and cannot be always-vpn.

## Consequences

Discovery data can inform router policy only within the work-pc scope. Repeater identities and always-vpn classification are rejected for that protected logical device.

## Verification

Split and full tunnel have separate acceptance branches.
