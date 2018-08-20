include(InstallPackageConfigFile)

install(DIRECTORY ./ DESTINATION ${BRO_SCRIPT_INSTALL_PATH} FILES_MATCHING
        PATTERN "site/local*" EXCLUDE
        PATTERN "test-all-policy.bro" EXCLUDE
        PATTERN "*.bro"
        PATTERN "*.sig"
        PATTERN "*.fp"
)

# Install all local* scripts as config files since they are meant to be
# user modify-able.
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local.bro
    ${BRO_SCRIPT_INSTALL_PATH}/site
    local.bro)
