project(Zeek-Plugin-Demo-Foo)

cmake_minimum_required(VERSION 3.5)

if (NOT ZEEK_DIST)
    message(FATAL_ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${ZEEK_DIST}/cmake)

include(ZeekPlugin)

zeek_plugin_begin(Demo Foo)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/Foo.cc)
zeek_plugin_bif(src/events.bif)
zeek_plugin_pac(src/foo.pac src/foo-protocol.pac src/foo-analyzer.pac)
zeek_plugin_end()
