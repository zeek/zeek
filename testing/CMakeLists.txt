if ( INSTALL_BTEST)
    install(DIRECTORY scripts/ DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/scripts
        USE_SOURCE_PERMISSIONS
        FILES_MATCHING PATTERN "diff-*")
    install(FILES btest/random.seed DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/data)
    if ( INSTALL_BTEST_PCAPS )
        install(DIRECTORY btest/Traces/ DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR}/data/pcaps)
    endif ()
endif ()
