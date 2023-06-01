project(Zeek-Plugin-Demo-Version)

cmake_minimum_required(VERSION 3.15)

if (NOT ZEEK_DIST)
    message(FATAL_ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${ZEEK_DIST}/cmake)

include(ZeekPlugin)

zeek_plugin_begin(Demo Version)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_end()
