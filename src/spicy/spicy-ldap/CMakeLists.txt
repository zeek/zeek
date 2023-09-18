cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(Messages LANGUAGES C)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(SpicyPlugin REQUIRED)

# Set mininum versions that this plugin needs. Make sure to use "x.y.z" format.
spicy_require_version("1.2.0")
spicy_plugin_require_version("0.99.0")
zeek_require_version("3.0.0")

if (NOT CMAKE_BUILD_TYPE)
    # Default to release build.
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
endif ()

add_subdirectory(analyzer)
