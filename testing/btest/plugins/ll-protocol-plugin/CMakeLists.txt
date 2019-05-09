
project(Zeek-LL-Plugin-Demo-Bar)

cmake_minimum_required(VERSION 2.6.3)

if ( NOT ZEEK_DIST )
    message(FATAL_ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${ZEEK_DIST}/cmake)

include(ZeekPlugin)

zeek_plugin_begin(LLDemo Bar)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/Bar.cc)
zeek_plugin_bif(src/events.bif)
zeek_plugin_end()
