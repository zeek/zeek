include(InstallPackageConfigFile)

install(DIRECTORY ./ DESTINATION ${POLICYDIR} FILES_MATCHING
        PATTERN "all.bro" EXCLUDE
        PATTERN "site/local.bro" EXCLUDE
        PATTERN "bro.init"
        PATTERN "*.bro"
        PATTERN "*.sig"
        PATTERN "*.osf"
)

# Install as a config file since the local.bro script is meant to be
# user modify-able.
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local.bro
    ${POLICYDIR}/site
    local.bro)

