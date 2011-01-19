include(CheckCXXSourceCompiles)
include(CheckCSourceCompiles)

# This autoconf variable is obsolete; it's portable to assume C89 and signal
# handlers returning void
set(RETSIGTYPE "void")
set(RETSIGVAL "")

check_c_source_compiles("
    #include <sys/types.h>
    #include <sys/socket.h>
    extern int socket(int, int, int);
    extern int connect(int, const struct sockaddr *, int);
    extern int send(int, const void *, int, int);
    extern int recvfrom(int, void *, int, int, struct sockaddr *, int *);
    int main() { return 0; }
" DO_SOCK_DECL)
if (DO_SOCK_DECL)
    message(STATUS "socket() and friends need explicit declaration")
endif ()

check_cxx_source_compiles("
    #include <stdlib.h>
    #include <syslog.h>
    extern \"C\" {
        int openlog(const char* ident, int logopt, int facility);
        int syslog(int priority, const char* message_fmt, ...);
        int closelog();
    }
    int main() { return 0; }
" SYSLOG_INT)
if (SYSLOG_INT)
    message(STATUS "syslog prototypes need declaration")
endif ()
