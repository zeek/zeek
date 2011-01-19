# A macro that checks whether optional sources exist and if they do, they
# are added to the build/install process, else a warning is issued
#
#         _dir: the subdir of the current source dir in which the optional
#               sources are located
# _packageName: a string that identifies the package
#     _varName: name of the variable indicating whether package is scheduled
#               to be installed

macro(CheckOptionalBuildSources _dir _packageName _varName)
    if (${_varName})
        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${_dir}/CMakeLists.txt)
            add_subdirectory(${_dir})
        else ()
            message(WARNING "${_packageName} source code does not exist in "
                            "${CMAKE_CURRENT_SOURCE_DIR}/${_dir} "
                            "so it will not be built or installed")
            set(${_varName} false)
        endif ()
    endif ()
endmacro(CheckOptionalBuildSources)
