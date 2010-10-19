# - Try to find libpcap include dirs and libraries 
#
# Usage of this module as follows:
#
#     find_package(BIND)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  BIND_ROOT_DIR             Set this variable to the root installation of BIND
#                            if the module has problems finding the proper
#                            installation path.
#
# Variables defined by this module:
#
#  BIND_FOUND                System has BIND, include and library dirs found
#  BIND_INCLUDE_DIR          The BIND include directories. 
#  BIND_LIBRARIES            All BIND libraries found.
#  BIND_LIBRARY              The BIND library required for ns_inittab and
#                            res_mkquery symbols.

find_path(BIND_ROOT_DIR
    NAMES include/resolv.h
)
mark_as_advanced(BIND_ROOT_DIR)

if (BIND_ROOT_DIR)
    set(BIND_INCLUDE_DIR ${BIND_ROOT_DIR}/include)
endif ()

find_library(BIND_LIBRARIES
    NAMES resolv bind
    HINTS ${BIND_ROOT_DIR}/lib
)

include(CheckCSourceCompiles)

# Find which library has the res_mkquery and ns_initparse symbols
set(CMAKE_REQUIRED_INCLUDES ${BIND_INCLUDE_DIR})
foreach (bindlib ${BIND_LIBRARIES})
    set(CMAKE_REQUIRED_LIBRARIES ${bindlib})

    check_c_source_compiles("
        #include <arpa/nameser.h>
        int main() {
            ns_initparse(0, 0, 0);
            return 0;
        }
" ns_initparse_works)

    check_c_source_compiles("
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <arpa/nameser.h>
        #include <resolv.h>
        int main() {
            int (*p)() = res_mkquery;
        }
" res_mkquery_works)

    unset(CMAKE_REQUIRED_LIBRARIES)

    if (ns_initparse_works AND res_mkquery_works)
        set(BIND_LIBRARY ${bindlib})
        break ()
    endif ()
endforeach ()
unset(CMAKE_REQUIRED_INCLUDES)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BIND DEFAULT_MSG
    BIND_LIBRARY
    BIND_INCLUDE_DIR
)

mark_as_advanced(BIND_LIBRARIES BIND_LIBRARY BIND_INCLUDE_DIR)
