
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginDoctest)

if (ENABLE_ZEEK_UNIT_TESTS)
    enable_testing()
    add_definitions(-DDOCTEST_CONFIG_SUPER_FAST_ASSERTS)
else ()
    add_definitions(-DDOCTEST_CONFIG_DISABLE)
endif ()

include(ZeekPlugin)

zeek_plugin_begin(Demo Doctest)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
