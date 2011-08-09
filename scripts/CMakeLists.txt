include(InstallPackageConfigFile)

install(DIRECTORY ./ DESTINATION ${BRO_SCRIPT_INSTALL_PATH} FILES_MATCHING
        PATTERN "all.bro" EXCLUDE
        PATTERN "site/local.bro" EXCLUDE
        PATTERN "*.bro"
        PATTERN "*.sig"
        PATTERN "*.osf"
)

# Install as a config file since the local.bro script is meant to be
# user modify-able.
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local.bro
    ${BRO_SCRIPT_INSTALL_PATH}/site
    local.bro)

