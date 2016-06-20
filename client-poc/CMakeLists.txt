cmake_minimum_required(VERSION 2.6)
PROJECT(wsclient)
ADD_DEFINITIONS(-Os -Wall --std=gnu99 -D_XOPEN_SOURCE=700 )

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")

ADD_EXECUTABLE(owsclient-wifiimport
	src/main.c
	src/wsubus-wifiimport.c
	src/wifiimport.c
	)

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(json NAMES json-c)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_PACKAGE(libwebsockets REQUIRED)
INCLUDE_DIRECTORIES(${LIBWEBSOCKETS_INCLUDE_DIRS})

TARGET_LINK_LIBRARIES(owsclient-wifiimport ${ubox} ${json} ${blobmsg_json} ${LIBWEBSOCKETS_LIBRARIES})

INSTALL(TARGETS owsclient-wifiimport RUNTIME DESTINATION usr/bin)
