cmake_minimum_required(VERSION 2.6)
PROJECT(owsd)
ADD_DEFINITIONS(-Os -Wall --std=gnu99 -D_XOPEN_SOURCE=700 )

INCLUDE_DIRECTORIES(include)
FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

SET(CMAKE_EXECUTABLE_LINK_C_FLAGS "")
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

SET(SOURCES
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

ADD_EXECUTABLE(owsd ${SOURCES})

FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(json NAMES json-c)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
TARGET_LINK_LIBRARIES(owsd ${ubox} ${ubus} ${json} ${blobmsg_json})

FIND_PACKAGE(libwebsockets REQUIRED)
INCLUDE_DIRECTORIES(${LIBWEBSOCKETS_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(owsd ${LIBWEBSOCKETS_LIBRARIES})

INCLUDE(CheckSymbolExists)
CHECK_SYMBOL_EXISTS(LWS_OPENSSL_SUPPORT "lws_config.h" LWS_HAS_SSL)

IF (DEFINED LWS_HAS_SSL)
	FIND_LIBRARY(ssl NAMES ssl)
	FIND_LIBRARY(crypto NAMES crypto)
	TARGET_LINK_LIBRARIES(owsd ${ssl} ${crypto})
ENDIF()

INSTALL(TARGETS owsd RUNTIME DESTINATION bin)
