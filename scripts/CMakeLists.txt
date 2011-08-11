include(InstallPackageConfigFile)

install(DIRECTORY ./ DESTINATION ${POLICYDIR} FILES_MATCHING
        PATTERN "site/local*" EXCLUDE
        PATTERN "*.bro"
        PATTERN "*.sig"
        PATTERN "*.fp"
)

# Install all local* scripts as config files since they are meant to be
# user modify-able.
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local.bro
    ${POLICYDIR}/site
    local.bro)
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local-manager.bro
    ${POLICYDIR}/site
    local-manager.bro)
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local-proxy.bro
    ${POLICYDIR}/site
    local-proxy.bro)
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local-worker.bro
    ${POLICYDIR}/site
    local-worker.bro)
