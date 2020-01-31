include(InstallPackageConfigFile)

install(DIRECTORY ./ DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH} FILES_MATCHING
        PATTERN "site/local*" EXCLUDE
        PATTERN "*.zeek"
        PATTERN "*.sig"
        PATTERN "*.fp"
)

# Install local script as a config file since it's meant to be modified directly.
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local.zeek
    ${ZEEK_SCRIPT_INSTALL_PATH}/site
    local.zeek)
