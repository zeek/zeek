project(Zeek-Plugin-Demo-Foo)

cmake_minimum_required(VERSION 3.15)

if (NOT BRO_DIST)
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

include(ZeekPlugin)

zeek_plugin_begin(Demo Foo)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/Foo.cc)
zeek_plugin_bif(src/events.bif)
zeek_plugin_end()
