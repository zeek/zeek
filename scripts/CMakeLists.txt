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
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local-manager.bro
    ${BRO_SCRIPT_INSTALL_PATH}/site
    local-manager.bro)
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local-proxy.bro
    ${BRO_SCRIPT_INSTALL_PATH}/site
    local-proxy.bro)
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local-worker.bro
    ${BRO_SCRIPT_INSTALL_PATH}/site
    local-worker.bro)
