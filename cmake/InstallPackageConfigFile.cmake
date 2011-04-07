include(InstallClobberImmune)

# This macro can be used to install configuration files which
# users are expected to modify after installation.  It will:
#
#   - Always install one version of the file with a .example suffix
#   - If binary packaging is enabled:
#     Install the file in the typical CMake fashion, but append to the
#     INSTALLED_CONFIG_FILES cache variable for use with the Mac package's
#     pre/post install scripts
#   - If binary packaging is not enabled:
#     Install the script in a way such that it will check at `make install`
#     time whether the file does not exist.  See InstallClobberImmune.cmake
#
#   _srcfile: the absolute path to the file to install
#   _dstdir: absolute path to the directory in which to install the file
#   _dstfilename: how to (re)name the file inside _dstdir

macro(InstallPackageConfigFile _srcfile _dstdir _dstfilename)
    set(_dstfile ${_dstdir}/${_dstfilename})

    # Always install the latest version of the file renamed as an example
    install(FILES ${_srcfile} DESTINATION ${_dstdir}
            RENAME ${_dstfilename}.example)

    if (BINARY_PACKAGING_MODE)
        # If packaging mode is enabled, always install the distribution's
        # version of the file.  The Mac package's pre/post install scripts
        # or native functionality of RPMs will take care of not clobbering it.
        install(FILES ${_srcfile} DESTINATION ${_dstdir} RENAME ${_dstfilename})
        # This cache variable is what the Mac package pre/post install scripts
        # use to avoid clobbering user-modified config files
        set(INSTALLED_CONFIG_FILES
            "${INSTALLED_CONFIG_FILES} ${_dstfile}" CACHE STRING "" FORCE)
    else ()
        # Have `make install` check at run time whether the file does not exist
        InstallClobberImmune(${_srcfile} ${_dstfile})
    endif ()
endmacro(InstallPackageConfigFile)
