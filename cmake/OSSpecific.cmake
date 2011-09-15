if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")

elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")

elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

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
    include(CheckCSourceCompiles)
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


