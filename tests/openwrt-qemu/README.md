# OpenWrt QEMU P2 acceptance

`run.sh` boots the SHA-256-pinned OpenWrt 25.12.5 x86_64 ext4 image in an
isolated qcow2 overlay under TCG. The host downloads exact, independently pinned
signed APKs for `dnsmasq-full` and `ip-full`; the guest installs only those local
files with signature verification and networking disabled. No guest package feed
is contacted.

The production dataplane then runs against real `fw4`, `nft`, `dnsmasq-full`,
and `ip`, reboots the guest, and verifies last-known-good recovery.

The suite covers successful apply/confirm, invalid nft and DNS candidates,
post-check rollback, commit-confirm timeout, crash recovery, reboot reconciliation,
immutable UCI configs, and bounded evidence collection. Run it on Linux with:

```sh
tests/openwrt-qemu/check-prereqs.sh
OPENWRT_QEMU_EVIDENCE_DIR=/tmp/routerd-qemu-evidence tests/openwrt-qemu/run.sh
```

The filogic kernel module cannot execute meaningfully in the x86_64 QEMU lab;
module and UAPI execution remains a real GL-MT6000 hardware gate.
