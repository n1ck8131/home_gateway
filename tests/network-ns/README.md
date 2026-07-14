# P2 Linux network namespace safety suite

`run.sh` is the only entrypoint. It builds one bounded lab driver, creates six
uniquely named namespaces, and exercises the production `dataplane.Controller`
and `apply.LinuxRuntime` through real `nft`, `ip` and `dnsmasq-full` calls.
Only the OpenWrt-only `fw4` and `/etc/init.d/dnsmasq reload` commands are
emulated by an argv-preserving runner.

Topology:

```text
client -> router -> WAN
             |
             +-> tunnel slot 1 -> internet
             |
             +-> tunnel slot 2 -> internet
```

Run only on a disposable Linux CI runner with root and network-namespace
support:

```sh
sudo tests/network-ns/run.sh
```

CI can request a stable, initially absent artifact directory:

```sh
sudo NETWORK_NS_EVIDENCE_DIR=/absolute/path/network-ns-evidence \
  tests/network-ns/run.sh
```

The entrypoint enforces a 15-minute outer deadline, caps Go compilation to one
logical processor and one package at a time, keeps a fixed process count, and
uses bounded TERM/KILL/wait cleanup. It does not invoke WSL, Docker or QEMU.
The emitted evidence directory is rejected if it exceeds 50 MiB.

The suite proves IPv4/IPv6 direct, VPN, scoped work-PC direct, TCP, UDP,
QUIC-shaped UDP, exact-apex, wildcard-subdomain, suffix and overlapping-domain
matching through real A/AAAA/CNAME nftset population and expiry. It also covers
shared-IP direct precedence, sticky established flows across an active-slot
switch, invalid validation rollback, explicit rollback, crash/boot recovery,
and twenty alternating physical tunnel-link removal/recreation no-leak cycles.
