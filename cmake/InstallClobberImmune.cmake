# Determines at `make install` time if a file, typically a configuration
# file placed in $PREFIX/etc, shouldn't be installed to prevent overwrite
# of an existing file.
#
# _srcfile: the file to install
# _dstfile: the absolute file name after installation

macro(InstallClobberImmune _srcfile _dstfile)
    install(CODE "
        if (EXISTS ${_dstfile})
            message(STATUS \"Skipping: ${_dstfile} (already exists)\")
        else ()
            message(STATUS \"Installing: ${_dstfile}\")
            # install() is not scriptable within install(), and
            # configure_file() is the next best thing
            configure_file(${_srcfile} ${_dstfile} COPY_ONLY)
            # TODO: create additional install_manifest files?
        endif ()
    ")
endmacro(InstallClobberImmune)
