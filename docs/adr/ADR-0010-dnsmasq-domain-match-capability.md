# ADR-0010: dnsmasq domain match capability

Status: Accepted

## Context

P1 models exact, suffix and wildcard domain matches. The OpenWrt P2 adapter uses `dnsmasq-full` nftset directives to populate nftables sets from DNS answers.

The dnsmasq selector consumed by this adapter performs label-boundary suffix matching and chooses the longest matching selector. An apex selector therefore also matches descendants. The wildcard syntax does not provide a reliable descendant-only nftset selector. A shadow-set workaround cannot remove a previously widened membership and does not preserve the requested policy.

## Decision

The P2 dnsmasq adapter accepts suffix matches only. It expands nested suffix boundaries so a more-specific selector retains every broader set membership that dnsmasq would otherwise hide through longest-match selection.

The adapter rejects exact and wildcard matches before `Transaction.Apply`. P1 retains these logical match types. A future hostname-aware DNS adapter needs a separate architecture decision and acceptance suite before production code can apply them.

## Consequences

P2 does not silently widen exact matches or silently drop wildcard matches. API and UI phases must expose the capability error until a hostname-aware adapter exists. Empty shadow nft sets are not rendered.

Managed suffix DNS keeps the ADR-0004 no-leak scope. Unmanaged DNS and browser DNS over HTTPS remain outside that guarantee.

## Verification

Focused tests reject exact and wildcard candidates before transaction staging. The network namespace suite confirms both rejections against the production controller and verifies suffix A, AAAA and CNAME set population, nested memberships, expiry and direct-over-VPN precedence with real dnsmasq and nftables.
