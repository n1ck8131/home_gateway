# OpenWrt QEMU scope

P0 prepares package metadata and CI contracts only. P2 owns x86_64 OpenWrt QEMU runtime tests.

The filogic kernel module cannot be executed meaningfully in the x86_64 QEMU lab; module and UAPI execution requires real GL-MT6000 hardware.
