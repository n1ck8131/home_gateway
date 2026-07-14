# OpenWrt QEMU P2 acceptance

`run.sh` boots the SHA-256-pinned OpenWrt 25.12.5 x86_64 ext4 image in an
isolated qcow2 overlay under TCG. The host downloads the complete APK dependency
closure for `dnsmasq-full` and `ip-full` from allowlisted OpenWrt HTTPS URLs and
verifies every exact SHA-256 pin. The guest verifies the uploaded files again,
then installs only those local APKs with networking and repositories disabled.
`--allow-untrusted` is required because local OpenWrt APKs are outside the guest
keyring trust path; the enforced trust boundary is the pinned SHA-256 manifest.

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
