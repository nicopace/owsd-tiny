cmake_minimum_required(VERSION 2.6)
PROJECT(owsd)
ADD_DEFINITIONS(-Os -Wall --std=gnu99 )

INCLUDE_DIRECTORIES(include)

#SET(CMAKE_EXECUTABLE_LINK_C_FLAGS "")
SET(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BUILD_DIR}/bin)

SET(SOURCES
	src/main.c
	src/wsubus.c
	src/ws_http.c
	)

ADD_EXECUTABLE(owsd ${SOURCES})

# FIND_LIBRARY(json NAMES json json-c)
# TODO use find_package and/or specify lws version
FIND_LIBRARY(lws NAMES websockets)
FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(json NAMES json-c)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
TARGET_LINK_LIBRARIES(owsd ${ubox} ${ubus} ${lws} ${json} ${blobmsg_json})

SET_TARGET_PROPERTIES(owsd PROPERTIES OUTPUT_NAME owsd)
INSTALL(TARGETS owsd RUNTIME DESTINATION bin)
