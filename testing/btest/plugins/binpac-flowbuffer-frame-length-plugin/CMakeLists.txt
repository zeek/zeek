project(Zeek-Plugin-Foo-FOO)

cmake_minimum_required(VERSION 3.15)

if (NOT ZEEK_DIST)
    message(FATAL_ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${ZEEK_DIST}/cmake)

include(ZeekPlugin)

zeek_plugin_begin(Foo FOO)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/FOO.cc)
zeek_plugin_bif(src/foo.bif)
zeek_plugin_pac(src/foo.pac)
zeek_plugin_end()
