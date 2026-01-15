include(FindPackageHandleStandardArgs)

function (set_zmq_version)
    file(STRINGS "${ZeroMQ_INCLUDE_DIR}/zmq.h" ZMQ_MAJOR_VERSION_H
         REGEX "^#define ZMQ_VERSION_MAJOR [0-9]+$")
    file(STRINGS "${ZeroMQ_INCLUDE_DIR}/zmq.h" ZMQ_MINOR_VERSION_H
         REGEX "^#define ZMQ_VERSION_MINOR [0-9]+$")
    file(STRINGS "${ZeroMQ_INCLUDE_DIR}/zmq.h" ZMQ_PATCH_VERSION_H
         REGEX "^#define ZMQ_VERSION_PATCH [0-9]+$")
    string(REGEX REPLACE "^.*MAJOR ([0-9]+)$" "\\1" ZMQ_MAJOR_VERSION "${ZMQ_MAJOR_VERSION_H}")
    string(REGEX REPLACE "^.*MINOR ([0-9]+)$" "\\1" ZMQ_MINOR_VERSION "${ZMQ_MINOR_VERSION_H}")
    string(REGEX REPLACE "^.*PATCH ([0-9]+)$" "\\1" ZMQ_PATCH_VERSION "${ZMQ_PATCH_VERSION_H}")

    set(ZeroMQ_VERSION "${ZMQ_MAJOR_VERSION}.${ZMQ_MINOR_VERSION}.${ZMQ_PATCH_VERSION}"
        PARENT_SCOPE)
endfunction ()

function (set_cppzmq_version)
    # Extract the version from
    file(STRINGS "${ZeroMQ_CPP_INCLUDE_DIR}/zmq.hpp" CPPZMQ_MAJOR_VERSION_H
         REGEX "^#define CPPZMQ_VERSION_MAJOR [0-9]+$")
    file(STRINGS "${ZeroMQ_CPP_INCLUDE_DIR}/zmq.hpp" CPPZMQ_MINOR_VERSION_H
         REGEX "^#define CPPZMQ_VERSION_MINOR [0-9]+$")
    file(STRINGS "${ZeroMQ_CPP_INCLUDE_DIR}/zmq.hpp" CPPZMQ_PATCH_VERSION_H
         REGEX "^#define CPPZMQ_VERSION_PATCH [0-9]+$")
    string(REGEX REPLACE "^.*MAJOR ([0-9]+)$" "\\1" CPPZMQ_MAJOR_VERSION
                         "${CPPZMQ_MAJOR_VERSION_H}")
    string(REGEX REPLACE "^.*MINOR ([0-9]+)$" "\\1" CPPZMQ_MINOR_VERSION
                         "${CPPZMQ_MINOR_VERSION_H}")
    string(REGEX REPLACE "^.*PATCH ([0-9]+)$" "\\1" CPPZMQ_PATCH_VERSION
                         "${CPPZMQ_PATCH_VERSION_H}")

    set(ZeroMQ_CPP_VERSION "${CPPZMQ_MAJOR_VERSION}.${CPPZMQ_MINOR_VERSION}.${CPPZMQ_PATCH_VERSION}"
        PARENT_SCOPE)
endfunction ()

set(AUXIL_CPPZMQ_DIR ${CMAKE_CURRENT_LIST_DIR}/../auxil/cppzmq)
find_library(ZeroMQ_LIBRARY NAMES zmq HINTS ${ZeroMQ_ROOT_DIR}/lib)
find_path(ZeroMQ_INCLUDE_DIR NAMES zmq.h HINTS ${ZeroMQ_ROOT_DIR}/include)

set_zmq_version()

find_path(ZeroMQ_CPP_INCLUDE_DIR NAMES zmq.hpp HINTS ${ZeroMQ_ROOT_DIR}/include)

if (ZeroMQ_CPP_INCLUDE_DIR)
    set_cppzmq_version()
endif ()

if (NOT ZeroMQ_CPP_VERSION)
    # Probably no zmq.hpp file, use the version from auxil
    set(ZeroMQ_CPP_INCLUDE_DIR ${AUXIL_CPPZMQ_DIR} CACHE FILEPATH "Include path for cppzmq" FORCE)
    set_cppzmq_version()
elseif (ZeroMQ_CPP_VERSION VERSION_LESS "4.9.0")
    message(STATUS "Found old cppzmq version ${ZeroMQ_CPP_VERSION}, using bundled version")
    set(ZeroMQ_CPP_INCLUDE_DIR ${AUXIL_CPPZMQ_DIR} CACHE FILEPATH "Include path for cppzmq" FORCE)
    set_cppzmq_version()
endif ()

find_package_handle_standard_args(
    ZeroMQ
    FOUND_VAR ZeroMQ_FOUND
    VERSION_VAR ZeroMQ_VERSION
    REQUIRED_VARS ZeroMQ_LIBRARY ZeroMQ_INCLUDE_DIR ZeroMQ_CPP_INCLUDE_DIR ZeroMQ_CPP_VERSION)

set(ZeroMQ_LIBRARIES ${ZeroMQ_LIBRARY})
set(ZeroMQ_INCLUDE_DIRS ${ZeroMQ_INCLUDE_DIR} ${ZeroMQ_CPP_INCLUDE_DIR})
set(ZeroMQ_FOUND ${ZeroMQ_FOUND})
