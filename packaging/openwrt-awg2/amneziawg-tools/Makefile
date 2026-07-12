include $(TOPDIR)/rules.mk

PKG_NAME:=amneziawg-tools
PKG_VERSION:=1.0.20260618.2
PKG_RELEASE:=1
PKG_SOURCE_VERSION:=1.0.20260618-2
PKG_SOURCE:=v$(PKG_SOURCE_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/
PKG_HASH:=cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_SOURCE_VERSION)
PKG_MAINTAINER:=Home Gateway Project
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYING

include $(INCLUDE_DIR)/package.mk

MAKE_PATH:=src
MAKE_VARS+=PLATFORM=linux WITH_WGQUICK=no WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no

define Package/amneziawg-tools
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=AmneziaWG 2 userspace tools
  URL:=https://github.com/amnezia-vpn/amneziawg-tools
  DEPENDS:= \
	+!BUSYBOX_CONFIG_IP:ip \
	+!BUSYBOX_CONFIG_FEATURE_IP_LINK:ip \
	+kmod-amneziawg
endef

define Package/amneziawg-tools/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/wg $(1)/usr/bin/awg
	$(INSTALL_BIN) ./files/amneziawg_watchdog $(1)/usr/bin/amneziawg_watchdog
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/amneziawg.sh $(1)/lib/netifd/proto/amneziawg.sh
endef

$(eval $(call BuildPackage,amneziawg-tools))
