install(
    DIRECTORY scripts/
    DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/scripts
    USE_SOURCE_PERMISSIONS FILES_MATCHING
    PATTERN "diff-*")
install(FILES btest/random.seed DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/data)

if (INSTALL_BTEST_PCAPS)
    install(DIRECTORY btest/Traces/ DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/data/pcaps)
endif ()

# The remainder is for backwards-compatability with existing Spicy zkg packages.
install(
    CODE "execute_process( \
    COMMAND ${CMAKE_COMMAND} -E create_symlink \
    ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/data \
    ${CMAKE_INSTALL_PREFIX}/share/zeek/tests \
    )")

install(DIRECTORY scripts/spicy/ DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/data/Scripts
        USE_SOURCE_PERMISSIONS)
