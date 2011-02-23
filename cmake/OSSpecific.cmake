include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)

if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    # alternate malloc is faster for FreeBSD, but needs more testing
    # need to add way to set this from the command line
    set(USE_NMALLOC true)

elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
    set(USE_NMALLOC true)

elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # The following may have a greater scope than just Darwin
    # (i.e. any platform w/ GCC < 4.1.0), but I've only seen
    # it on OS X 10.5, which has GCC 4.0.1, so the workaround
    # will be stuck here for now.
    #
    # See also http://gcc.gnu.org/bugzilla/show_bug.cgi?id=13943

    check_cxx_source_compiles("
        #include <math.h>
        #include <cstdlib>
        using namespace std;
        int main() {
            llabs(1);
            return 0;
        }
    " darwin_llabs_works)

    if (NOT darwin_llabs_works)
        # abs() should be used in this case, the long long version should
        # exist in the __gnu_cxx namespace
        set(DARWIN_NO_LLABS true)
    endif ()

elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(HAVE_LINUX true)

elseif (${CMAKE_SYSTEM_NAME} MATCHES "Solaris")
    set(SOCKET_LIBS nsl socket)

elseif (${CMAKE_SYSTEM_NAME} MATCHES "osf")
    # Workaround ip_hl vs. ip_vhl problem in netinet/ip.h
    add_definitions(-D__STDC__=2)

elseif (${CMAKE_SYSTEM_NAME} MATCHES "irix")
    list(APPEND CMAKE_C_FLAGS -xansi -signed -g3)
    list(APPEND CMAKE_CXX_FLAGS -xansi -signed -g3)

elseif (${CMAKE_SYSTEM_NAME} MATCHES "ultrix")
    list(APPEND CMAKE_C_FLAGS -std1 -g3)
    list(APPEND CMAKE_CXX_FLAGS -std1 -g3)

    check_c_source_compiles("
        #include <sys/types.h>
        int main() {
            void c(const struct a *);
            return 0;
        }
    " have_ultrix_const)
    if (NOT have_ultrix_const)
        set(NEED_ULTRIX_CONST_HACK true)
    endif ()

elseif (${CMAKE_SYSTEM_NAME} MATCHES "hpux" OR
        ${CMAKE_SYSTEM_NAME} MATCHES "HP-UX")
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS -Aa)
    set(CMAKE_REQUIRED_DEFINITIONS -D_HPUX_SOURCE)
    check_c_source_compiles("
        #include <sys/types.h>
        int main() {
            int frob(int, char *);
            return 0;
        }
    " have_ansi_prototypes)
    set(CMAKE_REQUIRED_FLAGS)
    set(CMAKE_REQUIRED_DEFINITIONS)

    if (have_ansi_prototypes)
        add_definitions(-D_HPUX_SOURCE)
        list(APPEND CMAKE_C_FLAGS -Aa)
        list(APPEND CMAKE_CXX_FLAGS -Aa)
    endif ()

    if (NOT have_ansi_prototypes)
        message(FATAL_ERROR "Can't get HPUX compiler to handle ANSI prototypes")
    endif ()
endif ()


