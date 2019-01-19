#
# Copyright (C) 2014-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libwebsockets-tiny
PKG_VERSION:=3.1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://codeload.github.com/warmcat/libwebsockets/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=db948be74c78fc13f1f1a55e76707d7baae3a1c8f62b625f639e8f2736298324

PKG_SOURCE_VERSION:=v$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_SOURCE_SUBDIR)

PKG_LICENSE:=LGPL-2.1+exception
PKG_LICENSE_FILES:=LICENSE

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_OPTIONS += -DLWS_IPV6=$(if $(CONFIG_IPV6),ON,OFF)
CMAKE_OPTIONS += -DLWS_WITHOUT_TESTAPPS=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_EXTENSIONS=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_DAEMONIZE=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_CLIENT=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_DEBUG=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_SSL=ON


define Package/libwebsockets-tiny
	SECTION:=libs
	CATEGORY:=Libraries
	TITLE:=libwebsockets-tiny
	URL:=https://libwebsockets.org
	MAINTAINER:=Karl Palsson <karlp@etactica.com>
	PROVIDES:= libwebsockets-tiny
endef

define Package/libwebsockets-tiny/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwebsockets.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libwebsockets-tiny))
