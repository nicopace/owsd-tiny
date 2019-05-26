cmake_minimum_required(VERSION 3.9)
project(owsd C)

add_definitions(-Os -std=gnu11 -fms-extensions -fplan9-extensions -D_XOPEN_SOURCE=700)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION FALSE)


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
	src/util_jsonrpc.c
        src/ubusx_acl.c
	)

find_package(libwebsockets REQUIRED)
find_package(LIBUBOX REQUIRED)
find_library(JSON_LIBRARIES NAMES json-c)

set(WSD_LINK websockets ${LIBUBOX_LIBRARIES} ${JSON_LIBRARIES})
set(WSD_INCLUDE ${LIBWEBSOCKETS_INCLUDE_DIRS})

find_library(UBUS_LIBRARIES NAMES ubus)
find_path(UBUS_INCLUDE_DIRS libubus.h)
list(APPEND WSD_LINK ${UBUS_LIBRARIES})
list(APPEND WSD_INCLUDE ${UBUS_INCLUDE_DIRS})

list(APPEND WSD_INCLUDE ${CMAKE_BINARY_DIR})

add_executable(owsd ${SOURCES})
target_link_libraries(owsd ${WSD_LINK})
include_directories(${WSD_INCLUDE})

install(TARGETS owsd RUNTIME DESTINATION bin)
