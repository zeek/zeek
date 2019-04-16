include(InstallPackageConfigFile)

install(DIRECTORY ./ DESTINATION ${BRO_SCRIPT_INSTALL_PATH} FILES_MATCHING
        PATTERN "site/local*" EXCLUDE
        PATTERN "test-all-policy.zeek" EXCLUDE
        PATTERN "*.zeek"
        PATTERN "*.sig"
        PATTERN "*.fp"
)

# Install all local* scripts as config files since they are meant to be
# user modify-able.
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local.zeek
    ${BRO_SCRIPT_INSTALL_PATH}/site
    local.zeek)
