find_package(PkgConfig)

pkg_check_modules(PC_LIBUBOX QUIET libubox)

find_path(LIBUBOX_INCLUDE_DIR libubox/uloop.h
   HINTS ${PC_LIBUBOX_INCLUDEDIR} ${PC_LIBUBOX_INCLUDE_DIRS} PATH_SUFFIXES libubox)

find_library(LIBUBOX_LIBRARY_ubox NAMES ubox
   HINTS ${PC_LIBUBOX_LIBDIR} ${PC_LIBUBOX_LIBRARY_DIRS})

find_library(LIBUBOX_LIBRARY_blobmsg_json NAMES blobmsg_json
   HINTS ${PC_LIBUBOX_LIBDIR} ${PC_LIBUBOX_LIBRARY_DIRS})

set(LIBUBOX_LIBRARIES ${LIBUBOX_LIBRARY_ubox} ${LIBUBOX_LIBRARY_blobmsg_json})
set(LIBUBOX_INCLUDE_DIRS ${LIBUBOX_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LIBUBOX DEFAULT_MSG LIBUBOX_LIBRARY_ubox LIBUBOX_LIBRARY_blobmsg_json LIBUBOX_INCLUDE_DIR)

mark_as_advanced(LIBUBOX_INCLUDE_DIR LIBUBOX_LIBRARY)
