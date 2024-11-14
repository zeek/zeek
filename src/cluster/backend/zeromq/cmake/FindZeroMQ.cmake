include(FindPackageHandleStandardArgs)

find_library(ZeroMQ_LIBRARY NAMES zmq HINTS ${ZeroMQ_ROOT_DIR}/lib)

find_path(ZeroMQ_INCLUDE_DIR NAMES zmq.h HINTS ${ZeroMQ_ROOT_DIR}/include)

find_path(ZeroMQ_CPP_INCLUDE_DIR NAMES zmq.hpp HINTS ${ZeroMQ_ROOT_DIR}/include)

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

if (ZeroMQ_CPP_INCLUDE_DIR)
    set_cppzmq_version()
endif ()

if (NOT ZeroMQ_CPP_VERSION)
    # Probably no zmq.hpp file, use the version from auxil
    set(ZeroMQ_CPP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/auxil/cppzmq"
        CACHE FILEPATH "Include path for cppzmq" FORCE)
    set_cppzmq_version()
elseif (ZeroMQ_CPP_VERSION VERSION_LESS "4.9.0")
    message(STATUS "Found old cppzmq version ${ZeroMQ_CPP_VERSION}, using bundled version")
    set(ZeroMQ_CPP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/auxil/cppzmq"
        CACHE FILEPATH "Include path for cppzmq" FORCE)
    set_cppzmq_version()
endif ()

message(STATUS "Using cppzmq ${ZeroMQ_CPP_VERSION} from ${ZeroMQ_CPP_INCLUDE_DIR}")

find_package_handle_standard_args(
    ZeroMQ FOUND_VAR ZeroMQ_FOUND REQUIRED_VARS ZeroMQ_LIBRARY ZeroMQ_INCLUDE_DIR
                                                ZeroMQ_CPP_INCLUDE_DIR ZeroMQ_CPP_VERSION)

set(ZeroMQ_LIBRARIES ${ZeroMQ_LIBRARY})
set(ZeroMQ_INCLUDE_DIRS ${ZeroMQ_INCLUDE_DIR} ${ZeroMQ_CPP_INCLUDE_DIR})
set(ZeroMQ_FOUND ${ZeroMQ_FOUND})
