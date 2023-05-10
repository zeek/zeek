include(InstallPackageConfigFile)

install(
    DIRECTORY ./
    DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH}
    FILES_MATCHING
    PATTERN "site/local*" EXCLUDE
    PATTERN "*.zeek"
    PATTERN "*.sig"
    PATTERN "*.fp")

# Install local script as a config file since it's meant to be modified
# directly.
InstallPackageConfigFile(${CMAKE_CURRENT_SOURCE_DIR}/site/local.zeek
                         ${ZEEK_SCRIPT_INSTALL_PATH}/site local.zeek)

# Substitute values in templated script files, and install them.
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/base/misc/installation.zeek.in
               ${CMAKE_CURRENT_BINARY_DIR}/base/misc/installation.zeek @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/base/misc/installation.zeek
        DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH}/base/misc)
