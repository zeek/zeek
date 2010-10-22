# - Try to find BinPAC binary and library
#
# Usage of this module as follows:
#
#     find_package(BinPAC)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  BinPAC_ROOT_DIR           Set this variable to the root installation of
#                            BinPAC if the module has problems finding the
#                            proper installation path.
#  BinPAC_PREFER_BUILD       Set this to true if BinPAC should be built
#                            from sources located in the root source
#                            directory in subidrectory 'binpac'.  The
#                            module will not look for BinPAC elsewhere.
#
# Variables defined by this module:
#
#  BINPAC_FOUND              System has BinPAC binary and library
#  BinPAC_EXE                The binpac executable
#  BinPAC_LIBRARY            The libbinpac.a library
#  BinPAC_INCLUDE_DIR        The binpac headers

if (BinPAC_PREFER_BUILD)
    # check if we can build BinPAC locally
    if (EXISTS ${CMAKE_SOURCE_DIR}/binpac/CMakeLists.txt)
        if (NOT BinPAC_EXE)
            # Display only first time
            message(STATUS "Building local version of BinPAC")
        endif ()
        # BinPAC's CMake project must declare:
        # BinPAC_EXE, BinPAC_LIBRARY, BinPAC_INCLUDE_DIR
        add_subdirectory(${CMAKE_SOURCE_DIR}/binpac)
    else ()
        message(WARNING "Option to build BinPAC from source selected, "
                        "but no sources found in ${CMAKE_SOURCE_DIR}/binpac")
    endif ()
else ()
    # look for BinPAC in standard locations or user-provided root
    find_path(BinPAC_ROOT_DIR
        NAMES include/binpac.h
    )

    find_file(BinPAC_EXE
        NAMES binpac
        HINTS ${BinPAC_ROOT_DIR}/bin
    )

    find_library(BinPAC_LIBRARY
        NAMES libbinpac.a
        HINTS ${BinPAC_ROOT_DIR}/lib
    )

    find_path(BinPAC_INCLUDE_DIR
        NAMES binpac.h
        HINTS ${BinPAC_ROOT_DIR}/include
    )
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BinPAC DEFAULT_MSG
    BinPAC_EXE
    BinPAC_LIBRARY
    BinPAC_INCLUDE_DIR
)

mark_as_advanced(
    BinPAC_ROOT_DIR
    BinPAC_EXE
    BinPAC_LIBRARY
    BinPAC_INCLUDE_DIR
)
