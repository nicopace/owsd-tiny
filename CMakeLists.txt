cmake_minimum_required(VERSION 2.6)
project(owsd C)
add_definitions(-Os -Wall -std=gnu11 -fms-extensions -fplan9-extensions -D_XOPEN_SOURCE=700 )

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")

set(WSD_NEED_SSL OFF CACHE BOOL "Fail if SSL is not available")
set(WSD_HAVE_UBUS ON CACHE BOOL "ubus RPC support" MARK_AS_ADVANCED)
set(WSD_HAVE_DBUS ON CACHE BOOL "DBus RPC support")
if (WSD_HAVE_DBUS)
	set(WSD_DBUS_OBJECTS_PATH "/se/inteno/iopsys" CACHE STRING
		"Path under which to (non-recursively) look for DBus objects")
endif()
set(WSD_USER_BLACKLIST_OLD ON CACHE BOOL "Support old way of limiting user to specific listen interface")

set(SOURCES
	src/main.c
	src/ws_http.c
	src/ws_http_serve.c
	src/wsubus.c
	src/rpc.c
	src/rpc_call.c
	src/rpc_list.c
	src/rpc_sub.c
	src/access_check.c
	src/local_stub.c
	src/util_jsonrpc.c
	)

find_library(JSON_LIBRARIES NAMES json-c)
find_package(libwebsockets REQUIRED)
set(WSD_LINK ubox blobmsg_json ${JSON_LIBRARIES} ${LIBWEBSOCKETS_LIBRARIES})
set(WSD_INCLUDE ${LIBWEBSOCKETS_INCLUDE_DIRS})

if (WSD_HAVE_UBUS)
	find_library(UBUS_LIBRARIES NAMES ubus)
	find_path(UBUS_INCLUDE_DIRS libubus.h)
	list(APPEND WSD_LINK ${UBUS_LIBRARIES})
	list(APPEND WSD_INCLUDE ${UBUS_INCLUDE_DIRS})
	# list(APPEND SOURCES ...)
endif()

if (WSD_HAVE_DBUS)
	find_package(DBus REQUIRED)
	list(APPEND WSD_LINK ${DBUS_LIBRARIES})
	list(APPEND WSD_INCLUDE ${DBUS_INCLUDE_DIRS})

	find_package(LibXml2 REQUIRED)
	list(APPEND WSD_LINK ${LIBXML2_LIBRARIES})
	list(APPEND WSD_INCLUDE ${LIBXML2_INCLUDE_DIR})

	list(APPEND SOURCES
		src/dbus-io.c
		src/dbus_rpc_list.c
		src/dubus_conversions_names.c
		src/dubus_conversions_types.c
	)
endif()

include(CheckSymbolExists)
check_symbol_exists(LWS_OPENSSL_SUPPORT "lws_config.h" LWS_HAS_SSL)
if (LWS_HAS_SSL)
	set(WSD_HAVE_SSL BOOL ON)
	find_package(OpenSSL REQUIRED)
	list(APPEND WSD_LINK ${OPENSSL_LIBRARIES})
	list(APPEND WSD_INCLUDE ${OPENSSL_INCLUDE_DIRS})
else()
	if (WSD_NEED_SSL)
		message (FATAL_ERROR "Didn't find SSL support in lws!")
	endif()
	set(WSD_HAVE_SSL BOOL OFF)
endif()

configure_file(src/owsd-config.in.h owsd-config.h ESCAPE_QUOTES)
list(APPEND WSD_INCLUDE ${CMAKE_BINARY_DIR})


add_executable(owsd ${SOURCES})
target_link_libraries(owsd ${WSD_LINK})
include_directories(${WSD_INCLUDE})

install(TARGETS owsd RUNTIME DESTINATION bin)
