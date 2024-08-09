include(FindPackageHandleStandardArgs)

find_library(ZeroMQ_LIBRARY NAMES libzmq.so HINTS ${ZeroMQ_ROOT_DIR}/lib)

find_path(ZeroMQ_INCLUDE_DIR NAMES zmq.h HINTS ${ZeroMQ_ROOT_DIR}/include)

find_path(ZeroMQ_CPP_INCLUDE_DIR NAMES zmq.hpp HINTS ${ZeroMQ_ROOT_DIR}/include)

find_package_handle_standard_args(
    ZeroMQ FOUND_VAR ZeroMQ_FOUND REQUIRED_VARS ZeroMQ_LIBRARY ZeroMQ_INCLUDE_DIR
                                                ZeroMQ_CPP_INCLUDE_DIR)

set(ZeroMQ_LIBRARIES ${ZeroMQ_LIBRARY})
set(ZeroMQ_INCLUDE_DIRS ${ZeroMQ_INCLUDE_DIR} ${ZeroMQ_CPP_INCLUDE_DIR})
set(ZeroMQ_FOUND ${ZeroMQ_FOUND})
