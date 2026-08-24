include $(TOPDIR)/rules.mk

PKG_NAME:=routerd
PKG_VERSION:=0.3.4
ROUTERD_PACKAGE_RELEASE?=2
ifeq ($(ROUTERD_PACKAGE_RELEASE),1)
else ifeq ($(ROUTERD_PACKAGE_RELEASE),2)
else
  $(error ROUTERD_PACKAGE_RELEASE must be 1 or 2)
endif
PKG_RELEASE:=$(ROUTERD_PACKAGE_RELEASE)
PKG_FLAGS:=nonshared
PKG_MAINTAINER:=Home Gateway Project
PKG_LICENSE:=LicenseRef-Home-Gateway
PKG_FILE_DEPENDS:=files/routerd files/routerd.init

include $(INCLUDE_DIR)/package.mk

# routerd is a fully static Go binary. Do not declare a false libc runtime edge.
PKG_DEFAULT_DEPENDS:=
PKG_SOURCE_DATE_EPOCH:=$(SOURCE_DATE_EPOCH)

define Package/routerd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Home Gateway routing policy service
  URL:=https://github.com/n1ck8131/home_gateway
endef

define Package/routerd/description
  Home Gateway policy, recovery and fail-closed dataplane controller.
endef

define Build/Compile
endef

define Package/routerd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/routerd $(1)/usr/bin/routerd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/routerd.init $(1)/etc/init.d/routerd
endef

$(eval $(call BuildPackage,routerd))
