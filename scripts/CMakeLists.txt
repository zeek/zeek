include(InstallPackageConfigFile)

install(DIRECTORY ./ DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH} FILES_MATCHING
        PATTERN "site/local*" EXCLUDE
        PATTERN "*.zeek"
        PATTERN "*.sig"
        PATTERN "*.fp"
)

if ( NOT BINARY_PACKAGING_MODE )
  # If the user has a local.bro file from a previous installation, prefer to
  # symlink local.zeek to it to avoid breaking their custom configuration --
  # because ZeekControl will now prefer to load local.zeek rather than local.bro
  # and we're about to install a default version of local.zeek.

  set(_local_bro_dst ${ZEEK_SCRIPT_INSTALL_PATH}/site/local.bro)
  set(_local_zeek_dst ${ZEEK_SCRIPT_INSTALL_PATH}/site/local.zeek)

  install(CODE "
    if ( \"\$ENV{DESTDIR}\" STREQUAL \"\" )
      if ( EXISTS \"${_local_bro_dst}\" AND NOT EXISTS \"${_local_zeek_dst}\" )
        message(STATUS \"WARNING: installed ${_local_zeek_dst} as symlink to ${_local_bro_dst}\")
        execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
          \"${_local_bro_dst}\" \"${_local_zeek_dst}\")
      endif ()
    endif ()
  ")
endif ()

# Install local script as a config file since it's meant to be modified directly.
InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/site/local.zeek
    ${ZEEK_SCRIPT_INSTALL_PATH}/site
    local.zeek)
