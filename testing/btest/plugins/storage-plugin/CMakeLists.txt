cmake_minimum_required(VERSION 3.15)

project(Zeek-Plugin-Storage-Demo)

if (NOT ZEEK_DIST)
    message(FATAL_ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${ZEEK_DIST}/cmake)

include(ZeekPlugin)

zeek_plugin_begin(Testing StorageDummy)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/StorageDummy.cc)
zeek_plugin_end()
