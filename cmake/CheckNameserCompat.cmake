include(CheckCSourceCompiles)

# Check whether the namser compatibility header is required
# This can be the case on the Darwin platform

check_c_source_compiles("
    #include <arpa/nameser.h>
    int main() { HEADER *hdr; int d = NS_IN6ADDRSZ; return 0; }"
    have_nameser_header)

if (NOT have_nameser_header)
    check_c_source_compiles("
        #include <arpa/nameser.h>
        #include <arpa/nameser_compat.h>
        int main() { HEADER *hdr; int d = NS_IN6ADDRSZ; return 0; }"
        NEED_NAMESER_COMPAT_H)
    if (NOT NEED_NAMESER_COMPAT_H)
        message(FATAL_ERROR
            "Asynchronous DNS support compatibility check failed.")
    endif ()
endif ()
