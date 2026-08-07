cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)
project(systemd-zeek-generator)

# If there's no PARENT_DIRECTORY, this is a standalone build.
get_directory_property(is_subproject PARENT_DIRECTORY)

if (NOT is_subproject)
    # Taken from RequireCXXStd for building standalone.
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_EXTENSIONS OFF)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

    set(_default_base_dir "/usr/local/zeek/")
    set(_default_etc_dir "/usr/local/zeek/etc/")
else ()
    set(_default_base_dir "${CMAKE_INSTALL_PREFIX}")
    set(_default_etc_dir "${ZEEK_ETC_INSTALL_DIR}")
    set(DOCTEST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/3rdparty/")
endif ()

# The systemd generator only does something where systemd runs, and working on
# it needs a Linux container or VM anyway, so it is off by default elsewhere.
set(_default ON)
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(_default OFF)
endif ()

option(ENABLE_ZEEK_SYSTEMD_GENERATOR "Enable building and installing zeek-systemd-generator"
       ${_default})

# zeek-cluster-layout-generator and the parsing it shares with the systemd
# generator are not systemd-specific and are useful on their own, so they are
# built wherever the sources compile.  They need unistd.h and friends, which
# rules out MSVC.
if (NOT MSVC)
    add_library(utils OBJECT src/utils.cc)
    add_library(zeek-cluster-config OBJECT src/zeek-cluster-config.cc)

    if (DOCTEST_INCLUDE_DIR)
        add_executable(utils-test src/utils-test.cc)
        target_include_directories(utils-test PRIVATE ${DOCTEST_INCLUDE_DIR})
        target_link_libraries(utils-test utils)
    endif ()

    add_executable(zeek-cluster-layout-generator src/zeek-cluster-layout-generator.cc)
    target_link_libraries(zeek-cluster-layout-generator zeek-cluster-config utils)
    install(TARGETS zeek-cluster-layout-generator RUNTIME DESTINATION bin)

    if (ENABLE_ZEEK_SYSTEMD_GENERATOR)
        add_library(systemd-unit OBJECT src/systemd-unit.cc)

        add_executable(zeek-systemd-generator src/zeek-systemd-generator.cc)
        target_compile_definitions(
            zeek-systemd-generator PRIVATE DEFAULT_ETC_DIR=\"${_default_etc_dir}\"
                                           DEFAULT_BASE_DIR=\"${_default_base_dir}\")

        target_link_libraries(zeek-systemd-generator zeek-cluster-config systemd-unit utils)

        install(TARGETS zeek-systemd-generator RUNTIME DESTINATION bin)
    endif ()

    if (is_subproject)
        # Install a default configuration at <PREFXI>etc/default/zeek
        include(InstallPackageConfigFile)
        InstallPackageConfigFile(${CMAKE_CURRENT_SOURCE_DIR}/etc/zeek/zeek.conf
                                 ${ZEEK_ETC_INSTALL_DIR}/zeek zeek.conf)
    endif ()
endif ()
