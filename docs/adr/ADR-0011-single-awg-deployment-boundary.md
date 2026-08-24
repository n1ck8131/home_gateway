# ADR-0011: Single AmneziaWG deployment boundary

Status: Accepted

## Context

P3 configures one AmneziaWG 2 (AWG2) server and one OpenWrt peer. The operation crosses an SSH boundary, handles private keys and can break router or VPS access when only one side succeeds.

## Decision

The VPS consumes a hash-verified, non-secret bundle. The bundle contains public transport metadata, pinned artifact digests and secret references. Parsed content receives a private semantic seal and is defensively copied before deployment, so exported Go fields cannot be changed after verification. A local runtime resolves secret references without placing secret bytes in Git, inventory, logs or process arguments.

VPS deployment uses an idempotent saga with explicit upgrade intent. Each mutation has compensation, and SSH hardening starts only after the recovery account succeeds independently. The bundle cannot assert that recovery proof itself.

The router installs a concrete endpoint host route through WAN before it activates the peer. The peer sets `route_allowed_ips=0` and `nohostroute=1`. It omits AWG `FwMark`; `routerd` remains the sole owner of marks and routing tables. Every apply, including a same-spec reconciliation, replays the idempotent UCI cleanup and configuration before health can mark the server available. Tunnel health changes only the P2 server inventory from terminal fail-closed to `default dev <awg-interface>`.

Router private keys remain in `/etc/routerd/secrets/` as root-owned mode `0600` files. The project-owned netifd helper reads the key through `private_key_file`; UCI stores only the non-secret path.

The first P3 server-to-router peer does not use an optional preshared key (PSK). A later PSK change must add a file-reference contract on both sides before either side enables it; secret bytes may not be stored in UCI.

## Consequences

The endpoint must be a static IP for the first P3 slice. Dynamic endpoint rotation requires a later transactional route update. Cross-host apply is not presented as atomic, and failed tunnel health never falls through to the WAN default route.

P3 software tests can validate contracts, ordering, idempotence and compensation without target access. Exact-kernel loading, router-to-VPS handshake, egress identity and recovery remain physical gates.

## Verification

Unit tests reject unknown fields, secret bytes, unsafe paths, post-verification bundle mutation, deployable documentation endpoints, `fwmark`, non-host endpoint routes and malformed or reordered UCI operations. Required deletes must precede writes, and same-spec reconciliation must run those deletes before health can publish availability. Failure injection verifies compensation and terminal P2 routes. Sanitized examples are marked as non-deployable. The OpenWrt package test verifies the `private_key_file` boundary and ephemeral setconf cleanup.
