# this is only for PKG_BUILD_DEPENDS:= - it's only building a static library
include $(TOPDIR)/rules.mk

PKG_NAME:=libwebsockets-static
PKG_VERSION:=3.1.0
PKG_RELEASE:=1

PKG_SOURCE:=libwebsockets-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=libwebsockets-$(PKG_VERSION)
PKG_SOURCE_URL:=https://codeload.github.com/warmcat/libwebsockets/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=db948be74c78fc13f1f1a55e76707d7baae3a1c8f62b625f639e8f2736298324

PKG_SOURCE_VERSION:=v$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_SOURCE_SUBDIR)

PKG_LICENSE:=LGPL-2.1+exception
PKG_LICENSE_FILES:=LICENSE

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

TARGET_CFLAGS += -flto
TARGET_LDLAGS += -flto

CMAKE_OPTIONS += -DLWS_IPV6=$(if $(CONFIG_IPV6),ON,OFF)
CMAKE_OPTIONS += -DLWS_WITHOUT_TESTAPPS=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_EXTENSIONS=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_DAEMONIZE=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_CLIENT=ON
CMAKE_OPTIONS += -DLWS_WITHOUT_DEBUG=ON
CMAKE_OPTIONS += -DLWS_WITH_SSL=OFF
CMAKE_OPTIONS += -DLWS_WITH_HTTP2=OFF
CMAKE_OPTIONS += -DLWS_WITH_SHARED=OFF
CMAKE_OPTIONS += -DLWS_WITH_STATIC=ON

define Package/libwebsockets-static
	SECTION:=libs
	CATEGORY:=Libraries
	TITLE:=libwebsockets-static
	URL:=https://libwebsockets.org
	PROVIDES:= libwebsockets-static
endef

$(eval $(call BuildPackage,libwebsockets-static))
