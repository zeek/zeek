# Calling this macro with the name of a list variable will modify that
# list such that any third party libraries that do not come with a
# vanilla Mac OS X system will be replaced by an adjusted library that
# has an install_name relative to the location of any executable that
# links to it.
#
# Also, it will schedule the modified libraries for installation in a
# 'support_libs' subdirectory of the CMAKE_INSTALL_PREFIX.
#
# The case of third party libraries depending on other third party
# libraries is currently not handled by this macro.
#
# Ex.
#
# set(libs /usr/lib/libz.dylib
#             /usr/lib/libssl.dylib
#             /usr/local/lib/libmagic.dylib
#             /usr/local/lib/libGeoIP.dylib
#             /usr/local/lib/somestaticlib.a)
#
# include(ChangeMacInstallNames)
# ChangeMacInstallNames(libs)
#
# Should result in ${libs} containing:
#             /usr/lib/libz.dylib
#             /usr/lib/libssl.dylib
#             ${CMAKE_BINARY_DIR}/darwin_support_libs/libmagic.dylib
#             ${CMAKE_BINARY_DIR}/darwin_support_libs/libGeoIP.dylib
#             /usr/local/lib/somestaticlib.a
#
# such that we can now do:
#
# add_executable(some_exe ${srcs})
# target_link_libraries(some_exe ${libs})
#
# Any binary packages created from such a build should be self-contained
# and provide working installs on vanilla OS X systems.

macro(ChangeMacInstallNames libListVar)
    if (APPLE)
        find_program(INSTALL_NAME_TOOL install_name_tool)

        set(MAC_INSTALL_NAME_DEPS)
        set(SUPPORT_BIN_DIR ${CMAKE_BINARY_DIR}/darwin_support_libs)
        set(SUPPORT_INSTALL_DIR support_libs)

        file(MAKE_DIRECTORY ${SUPPORT_BIN_DIR})

        foreach (_lib ${${libListVar}})
            # only care about install_name for shared libraries that are
            # not shipped in Apple's vanilla OS X installs
            string(REGEX MATCH ^/usr/lib/* apple_provided_lib ${_lib})
            string(REGEX MATCH dylib$ is_shared_lib ${_lib})

            if (NOT apple_provided_lib AND is_shared_lib)
                get_filename_component(_libname ${_lib} NAME)
                set(_adjustedLib ${SUPPORT_BIN_DIR}/${_libname})
                set(_tmpLib
                    ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${_libname})

                # make a tempory copy so we can adjust permissions
                configure_file(${_lib} ${_tmpLib} COPYONLY)

                # copy to build directory with correct write permissions
                file(COPY ${_tmpLib}
                    DESTINATION ${SUPPORT_BIN_DIR}
                    FILE_PERMISSIONS OWNER_READ OWNER_WRITE
                                     GROUP_READ WORLD_READ)

                # remove the old library from the list provided as macro
                # argument and add the new library with modified install_name
                list(REMOVE_ITEM ${libListVar} ${_lib})
                list(APPEND ${libListVar} ${_adjustedLib})

                # update the install target to install the third party libs
                # with modified install_name
                install(FILES ${_adjustedLib}
                    DESTINATION ${SUPPORT_INSTALL_DIR})

                # perform the install_name change
                execute_process(COMMAND install_name_tool -id
                    @executable_path/../${SUPPORT_INSTALL_DIR}/${_libname}
                    ${_adjustedLib})
            endif ()
        endforeach ()
    endif ()
endmacro()
