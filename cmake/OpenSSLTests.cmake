include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)

check_c_source_compiles("
    #include <openssl/ssl.h>
    int main() { return 0; }
" including_ssl_h_works)

if (NOT including_ssl_h_works)
    # On Red Hat we may need to include Kerberos header.
    set(CMAKE_REQUIRED_INCLUDES "/usr/kerberos/include")
    check_c_source_compiles("
        #include <krb5.h>
        #include <openssl/ssl.h>
        int main() { return 0; }
    " NEED_KRB5_H)
    unset(CMAKE_REQUIRED_INCLUDES)
    if (NOT NEED_KRB5_H)
        message(FATAL_ERROR
            "OpenSSL test failure.  See CmakeError.log for details.")
    else ()
        message(STATUS "OpenSSL requires Kerberos header")
        include_directories("/usr/kerberos/include")
    endif ()
endif ()

# check for OPENSSL_add_all_algorithms_conf function
# and thus OpenSSL >= v0.9.7
set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
check_c_source_compiles("
    #include <openssl/evp.h>
    int main() {
        OPENSSL_add_all_algorithms_conf();
        return 0;
    }
" openssl_greater_than_0_9_7)
unset(CMAKE_REQUIRED_LIBRARIES)
if (NOT openssl_greater_than_0_9_7)
    message(FATAL_ERROR "OpenSSL >= v0.9.7 required")
endif ()

set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
check_cxx_source_compiles("
#include <openssl/x509.h>
    int main() {
        const unsigned char** cpp = 0;
        X509** x =0;
        d2i_X509(x, cpp, 0);
        return 0;
    }
" OPENSSL_D2I_X509_USES_CONST_CHAR)

if (NOT OPENSSL_D2I_X509_USES_CONST_CHAR)
    # double check that it compiles without const
    check_cxx_source_compiles("
        #include <openssl/x509.h>
        int main() {
            unsigned char** cpp = 0;
            X509** x =0;
            d2i_X509(x, cpp, 0);
            return 0;
        }
        " OPENSSL_D2I_X509_USES_CHAR)
    if (NOT OPENSSL_D2I_X509_USES_CHAR)
        message(FATAL_ERROR
            "Can't determine if openssl_d2i_x509() takes const char parameter")
    endif ()
endif ()
unset(CMAKE_REQUIRED_LIBRARIES)
