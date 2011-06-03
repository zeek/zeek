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
#  BIND_LIBRARY              The BIND library (if any) required for
#                            ns_inittab and res_mkquery symbols

find_path(BIND_ROOT_DIR
    NAMES include/resolv.h
)

find_path(BIND_INCLUDE_DIR
    NAMES resolv.h
    HINTS ${BIND_ROOT_DIR}/include
)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    # the static resolv library is preferred because
    # on some systems, the ns_initparse symbol is not
    # exported in the shared library (strangely)
    # see http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=291609
    set(bind_libs none libresolv.a resolv bind)
else ()
    set(bind_libs none resolv bind)
endif ()

include(CheckCSourceCompiles)

# Find which library has the res_mkquery and ns_initparse symbols
set(CMAKE_REQUIRED_INCLUDES ${BIND_INCLUDE_DIR})
foreach (bindlib ${bind_libs})
    if (NOT ${bindlib} MATCHES "none")
        find_library(BIND_LIBRARY
            NAMES ${bindlib}
            HINTS ${BIND_ROOT_DIR}/lib
        )
    endif ()

    set(CMAKE_REQUIRED_LIBRARIES ${BIND_LIBRARY})

    check_c_source_compiles("
        #include <arpa/nameser.h>
        int main() {
            ns_initparse(0, 0, 0);
            return 0;
        }
" ns_initparse_works_${bindlib})

    check_c_source_compiles("
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <arpa/nameser.h>
        #include <resolv.h>
        int main() {
            int (*p)() = res_mkquery;
        }
" res_mkquery_works_${bindlib})

    set(CMAKE_REQUIRED_LIBRARIES)

    if (ns_initparse_works_${bindlib} AND res_mkquery_works_${bindlib})
        break ()
    else ()
        set(BIND_LIBRARY BIND_LIBRARY-NOTFOUND)
    endif ()
endforeach ()
set(CMAKE_REQUIRED_INCLUDES)

include(FindPackageHandleStandardArgs)

if (ns_initparse_works_none AND res_mkquery_works_none)
    # system does not require linking to a BIND library
    find_package_handle_standard_args(BIND DEFAULT_MSG
        BIND_INCLUDE_DIR
    )
else ()
    find_package_handle_standard_args(BIND DEFAULT_MSG
        BIND_LIBRARY
        BIND_INCLUDE_DIR
    )
endif ()

mark_as_advanced(
    BIND_ROOT_DIR
    BIND_LIBRARY
    BIND_INCLUDE_DIR
)
