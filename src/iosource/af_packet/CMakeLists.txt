
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeekPluginAF_Packet)

include(ZeekPlugin)
include(CheckSymbolExists)

zeek_plugin_begin(Zeek AF_Packet)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/AF_Packet.cc)
zeek_plugin_cc(src/RX_Ring.cc)
zeek_plugin_bif(src/af_packet.bif)
zeek_plugin_dist_files(zeekctl/af_packet.py README COPYING VERSION)
zeek_plugin_end()

check_symbol_exists(TP_STATUS_CSUM_VALID linux/if_packet.h HAVE_TP_STATUS_CSUM_VALID)
if (NOT HAVE_TP_STATUS_CSUM_VALID)
    message(STATUS "Checksum offloading to the kernel might not be fully supported.")
endif ()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
