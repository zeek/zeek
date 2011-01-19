# A wrapper macro around the standard CMake find_package macro that
# facilitates displaying better error messages by default, or even
# accepting custom error messages on a per package basis.
#
# If a package is not found, then the MISSING_PREREQS variable gets
# set to true and either a default or custom error message appended
# to MISSING_PREREQ_DESCS.
#
# The caller can use these variables to display a list of any missing
# packages and abort the build/configuration if there were any.
# 
# Use as follows:
#
# include(FindRequiredPackage)
# FindRequiredPackage(Perl)
# FindRequiredPackage(FLEX "You need to install flex (Fast Lexical Analyzer)")
#
# if (MISSING_PREREQS)
#    foreach (prereq ${MISSING_PREREQ_DESCS})
#        message(SEND_ERROR ${prereq})
#    endforeach ()
#    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
# endif ()

macro(FindRequiredPackage packageName)
    find_package(${packageName})
    string(TOUPPER ${packageName} canonPackageName)
    if (NOT ${canonPackageName}_FOUND)
        set(MISSING_PREREQS true)

        set(customDesc)
        foreach (descArg ${ARGN})
            set(customDesc "${customDesc} ${descArg}")
        endforeach ()

        if (customDesc)
            # append the custom error message that was provided as an argument
            list(APPEND MISSING_PREREQ_DESCS ${customDesc})
        else ()
            list(APPEND MISSING_PREREQ_DESCS
                 " Could not find prerequisite package '${packageName}'")
        endif ()
    endif ()
endmacro(FindRequiredPackage)
