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

    set(_default_config_file "/usr/local/zeek/etc/zeek/zeek.conf")
    set(_default_base_dir "/usr/local/zeek/")
else ()
    set(_default_config_file "${ZEEK_ETC_INSTALL_DIR}/zeek/zeek.conf")
    set(_default_base_dir "${CMAKE_INSTALL_PREFIX}")
endif ()

set(_default ON)
if (MSVC)
    set(_default OFF)
endif ()

# Build the generator everywhere unless explicitly disabled. Mostly
# for developer testing.
option(ENABLE_ZEEK_SYSTEMD_GENERATOR "Enable building and installing zeek-systemd-generator"
       ${_default})
if (ENABLE_ZEEK_SYSTEMD_GENERATOR)

    # Separate supporting libraries that aren't systemd specific.
    add_library(systemd-generator OBJECT src/systemd-unit.cc)
    add_library(zeek-cluster-config OBJECT src/zeek-cluster-config.cc)

    add_executable(zeek-systemd-generator src/zeek-systemd-generator.cc)
    target_compile_definitions(
        zeek-systemd-generator PRIVATE DEFAULT_CONFIG_FILE=\"${_default_config_file}\"
                                       DEFAULT_BASE_DIR=\"${_default_base_dir}\")

    target_link_libraries(zeek-systemd-generator systemd-generator zeek-cluster-config)

    add_executable(zeek-cluster-layout-generator src/zeek-cluster-layout-generator.cc)

    install(TARGETS zeek-systemd-generator RUNTIME DESTINATION bin)
    install(TARGETS zeek-cluster-layout-generator RUNTIME DESTINATION bin)

    if (is_subproject)
        # Install a default configuration at <PREFXI>etc/default/zeek
        include(InstallPackageConfigFile)
        InstallPackageConfigFile(${CMAKE_CURRENT_SOURCE_DIR}/etc/zeek/zeek.conf
                                 ${ZEEK_ETC_INSTALL_DIR}/zeek zeek.conf)
    endif ()
endif ()
