include(InstallPackageConfigFile)

# Remove scripts that may be left over from a previous installation.
# This can help prevent outdated scripts from loading things that
# are no longer supposed to exist.
# Note: CMake guarantees the order of install()'s as they're declared
# within a directory to match the order they're actually performed, but
# claims undefined ordering across directories.  Practically, they
# comment it's only undefined for *descendent* directories, but
# *sibling* directories will have a reliable install() ordering based
# on the order of add_subdirectory().
install(CODE "
    execute_process(COMMAND
                    \"${CMAKE_COMMAND}\" -E remove_directory
                    \"${BRO_SCRIPT_INSTALL_PATH}/base\")
    execute_process(COMMAND
                    \"${CMAKE_COMMAND}\" -E remove_directory
                    \"${BRO_SCRIPT_INSTALL_PATH}/policy\")
")

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
