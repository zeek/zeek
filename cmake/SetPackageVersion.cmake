# Sets CPack version variables by splitting the first macro argument
# using "." as a delimiter.  If the length of the split list is
# greater than 2, all remaining elements are tacked on to the patch
# level version.

macro(SetPackageVersion _version)
    string(REPLACE "." " " version_numbers ${_version})
    separate_arguments(version_numbers)

    list(GET version_numbers 0 CPACK_PACKAGE_VERSION_MAJOR)
    list(REMOVE_AT version_numbers 0)
    list(GET version_numbers 0 CPACK_PACKAGE_VERSION_MINOR)
    list(REMOVE_AT version_numbers 0)
    list(LENGTH version_numbers version_length)

    while (version_length GREATER 0)
        list(GET version_numbers 0 patch_level)
        if (CPACK_PACKAGE_VERSION_PATCH)
            set(CPACK_PACKAGE_VERSION_PATCH
                "${CPACK_PACKAGE_VERSION_PATCH}.${patch_level}")
        else ()
            set(CPACK_PACKAGE_VERSION_PATCH ${patch_level})
        endif ()
        list(REMOVE_AT version_numbers 0)
        list(LENGTH version_numbers version_length)
    endwhile ()
endmacro(SetPackageVersion)
