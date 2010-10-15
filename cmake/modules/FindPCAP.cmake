# - Try to find libpcap include dirs and libraries 
#
# Usage of this module as follows:
#
#     find_package(PCAP)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  PCAP_ROOT                 Preferred installation prefix for searching for
#                            libpcap, set this if the module has problems
#                            finding the proper installation path.
#  PCAP_INCLUDEDIR           Set this to the include directory of libpcap if
#                            the module has problems finding the installation
#                            path.
#  PCAP_LIBRARYDIR           Set this to the library directory of libpcap if
#                            the module has problems finding the installation
#                            path.
#
# Variables defined by this module:
#
#  PCAP_FOUND                System has libpcap, include and library dirs found
#  PCAP_INCLUDE_DIR          The libpcap include directories. 
#  PCAP_LIBRARY              The libpcap library.

if (PCAP_ROOT)
    message(STATUS "Searching for libpcap rooted in: ${PCAP_ROOT}")
    set(PCAP_ADDITIONAL_INCLUDE_SEARCH_DIRS ${PCAP_ROOT}/include)
    set(PCAP_ADDITIONAL_LIBRARY_SEARCH_DIRS ${PCAP_ROOT}/lib)
endif ()

if (PCAP_INCLUDEDIR)
    message(STATUS "Searching for libpcap headers in: ${PCAP_INCLUDEDIR}")
    set(PCAP_ADDITIONAL_INCLUDE_SEARCH_DIRS ${PCAP_INCLUDEDIR})
endif ()

if (PCAP_LIBRARYDIR)
    message(STATUS "Searching for libpcap libraries in: ${PCAP_LIBRARYDIR}")
    set(PCAP_ADDITIONAL_LIBRARY_SEARCH_DIRS ${PCAP_LIBRARYDIR})
endif ()

find_path(PCAP_INCLUDE_DIR
    NAMES
        pcap.h
    PATHS
        ${PCAP_ADDITIONAL_INCLUDE_SEARCH_DIRS}
)

find_library(PCAP_LIBRARY
    NAMES
        pcap
    PATHS
        ${PCAP_ADDITIONAL_LIBRARY_SEARCH_DIRS}
)

if (PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    set(PCAP_FOUND true)
endif ()

if (PCAP_FOUND)
    if (NOT PCAP_FIND_QUIETLY)
        message(STATUS "Found libpcap")
    endif ()
else ()
    if (PCAP_FIND_REQUIRED)
        message(FATAL_ERROR "Could not find required libpcap")
    endif ()
endif ()

mark_as_advanced(
    PCAP_INCLUDE_DIR
    PCAP_LIBRARY
)
