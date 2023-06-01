cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

find_package(PythonLibs REQUIRED)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

# Our plugin source and scripts are in a subdirectory
set(BRO_PLUGIN_BASE "${CMAKE_CURRENT_SOURCE_DIR}/plugin")

include(ZeekPlugin)

include_directories(BEFORE ${PYTHON_INCLUDE_DIR})

zeek_plugin_begin(Zeek PyLib)

file(GLOB cc_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/*.cc")
foreach (file ${cc_files})
    zeek_plugin_cc(${file})
endforeach ()

file(GLOB bif_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/*.bif")
foreach (file ${bif_files})
    zeek_plugin_bif(${file})
endforeach ()

zeek_plugin_dist_files(README VERSION)
zeek_plugin_link_library(${PYTHON_LIBRARY})
zeek_plugin_end()
