#
# Copyright (C) 2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=owsd
PKG_VERSION:=0.99
PKG_RELEASE:=1

PKG_MAINTAINER:=Sartura Support for Inteno <support-inteno@sartura.hr>
PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DEPENDS:=libwebsockets-static

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_SOURCE_DIR=$(CURDIR)/../../

define Package/owsd
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+ubus +ubox +libjson-c +libblobmsg-json +rpcd
  TITLE:=owsd daemon
endef

define Package/owsd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/owsd $(1)/usr/bin/owsd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/owsd.init $(1)/etc/init.d/owsd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/owsd.config $(1)/etc/config/owsd
endef

define Package/owsd-testdata
	$(call Package/owsd)
	TITLE += (Test certs and rpcd ACLs for running automated tests)
	DEPENDS := owsd +rpcd-mod-file
endef

define Package/owsd/description
 Web socket ubus daemon
endef

define Package/owsd-testdata/install
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/res/owsd-test.json $(1)/usr/share/rpcd/acl.d/owsd-test.json
	$(INSTALL_DIR) $(1)/usr/share/owsd/
	$(INSTALL_DIR) $(1)/www/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/res/webdemo/index.html $(1)/www/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/res/webdemo/script.js $(1)/www/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/res/webdemo/style.css $(1)/www/
endef

define Package/owsd-testdata/postinst
#!/bin/sh
set -e
uci delete rpcd.owsd_test 2>/dev/null || true
uci set rpcd.owsd_test=login
uci set rpcd.owsd_test.username="owsd_test"
uci set rpcd.owsd_test.password="x"
uci add_list rpcd.owsd_test.read='test-calls'
uci add_list rpcd.owsd_test.read='test-events'
uci commit
endef

define Package/owsd-testdata/prerm
#!/bin/sh
set -e
uci delete rpcd.owsd_test
uci commit
endef

$(eval $(call BuildPackage,owsd))
$(eval $(call BuildPackage,owsd-testdata))
