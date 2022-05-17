# Spicy needs the full prefix for Flex and Bison while Zeek captures only the
# paths to the executables. Derive the prefixes from the binary paths under the
# assumption that their bindir is under their prefix (which also implies that
# one such prefix even exists).
if ( NOT FLEX_EXECUTABLE )
   find_package(FLEX REQUIRED)
endif ()
get_filename_component(dir ${FLEX_EXECUTABLE} DIRECTORY ABSOLUTE)
set(FLEX_ROOT ${dir}/..)

if ( NOT BISON_EXECUTABLE )
   find_package(BISON REQUIRED)
endif ()
get_filename_component(dir ${BISON_EXECUTABLE} DIRECTORY ABSOLUTE)
set(BISON_ROOT ${dir}/..)

# We currently only support building against statically linked Spicy libraries.
# This is due to global state held in the Spicy and HILTI runtime libraries. If
# we would like Spicy dynamically this global state would end up the the final
# binary once via the static link of the runtime libraries into Zeek (needed to
# make sure we can e.g., load arbitrary HLTO files), and once as a link
# dependency of spicy-plugin. This can lead to e.g. consistency issues during
# execution or the problem during teardown where the same global might be
# cleaned up multiple times.
set(BUILD_SHARED_LIBS OFF)

# Spicy uses slightly less strict warnings than Zeek proper. Mute a few warnings for Spicy.
# NOTE: Compiler flags are inherited down the directory tree, so in order to
# set these flags we do need a customizable subdirectory above the Spicy
# sources.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-braces")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-vla")

# The script generating precompiled headers for Spicy expects a different build
# system layout than provided for a bundled Spicy, disable it.
set(HILTI_DEV_PRECOMPILE_HEADERS OFF)

add_subdirectory(spicy)
