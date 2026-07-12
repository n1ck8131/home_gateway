include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=kmod-amneziawg
PKG_VERSION:=1.0.20260611
PKG_RELEASE:=1
PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/archive/refs/tags/
PKG_HASH:=e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/amneziawg-linux-kernel-module-$(PKG_VERSION)
PKG_MAINTAINER:=Home Gateway Project
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYING
PKG_EXTMOD_SUBDIRS:=src

include $(INCLUDE_DIR)/package.mk

define KernelPackage/amneziawg
  SUBMENU:=Network Support
  TITLE:=AmneziaWG 2 kernel module
  URL:=https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
  DEPENDS:=+kmod-crypto-lib-chacha20poly1305 +kmod-crypto-lib-curve25519 +kmod-udptunnel4 +IPV6:kmod-udptunnel6
  FILES:=$(PKG_BUILD_DIR)/src/amneziawg.ko
  AUTOLOAD:=$(call AutoProbe,amneziawg)
endef

define KernelPackage/amneziawg/description
  Official AmneziaWG 2 kernel module packaged for the pinned Home Gateway OpenWrt target.
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)/src" \
		WIREGUARD_VERSION="$(PKG_VERSION)" \
		modules
endef

$(eval $(call KernelPackage,amneziawg))
