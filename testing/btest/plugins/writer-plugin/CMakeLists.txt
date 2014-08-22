
project(Bro-Plugin-Demo-Foo)

cmake_minimum_required(VERSION 2.6.3)

if ( NOT BRO_DIST )
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

include(BroPlugin)

bro_plugin_begin(Demo Foo)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/Foo.cc)
bro_plugin_end()
