cmake_minimum_required(VERSION 3.15)

project(Zeek-Plugin-Demo-Foo)

if (NOT ZEEK_DIST)
    message(FATAL_ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${ZEEK_DIST}/cmake)

include(ZeekPlugin)

zeek_add_plugin(
    Demo Foo
    SOURCES src/Plugin.cc src/Foo.cc)
