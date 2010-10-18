if (USE_OPENSSL)
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
            message(WARNING "Can't compile OpenSSL test; disabling OpenSSL")
            set(USE_OPENSSL false)
        else ()
            message(STATUS "OpenSSL requires Kerberos header")
            include_directories("/usr/kerberos/include")
        endif ()
    endif ()
endif()

if (USE_OPENSSL)
    # check for OPENSSL_add_all_algorithms_conf function
    # and thus OpenSSL >= v0.9.7
    set(CMAKE_REQUIRED_LIBRARIES crypto ssl)
    check_c_source_compiles("
        #include <openssl/evp.h>
        int main() {
            OPENSSL_add_all_algorithms_conf();
            return 0;
        }
    " USE_OPENSSL)
    unset(CMAKE_REQUIRED_LIBRARIES)
    if (NOT USE_OPENSSL)
        message(WARNING "OpenSSL >= v0.9.7 required; disabling OpenSSL")
    endif ()
endif ()

if (USE_OPENSSL)
    set(CMAKE_REQUIRED_LIBRARIES crypto)
    file(READ "${CONFTEST_DIR}/openssl_d2i_x509_const.c" CONFTEST)
    check_cxx_source_compiles("${CONFTEST}" OPENSSL_D2I_X509_USES_CONST_CHAR)
    if (NOT OPENSSL_D2I_X509_USES_CONST_CHAR)
        file(READ "${CONFTEST_DIR}/openssl_d2i_x509.c" CONFTEST)
        # double check
        check_cxx_source_compiles("${CONFTEST}" OPENSSL_D2I_X509_USES_CHAR)
        if (NOT OPENSSL_D2I_X509_USES_CHAR)
            message(FATAL_ERROR "Can't determine if openssl_d2i_x509() takes a const char parameter")
        endif (NOT OPENSSL_D2I_X509_USES_CHAR)
    endif (NOT OPENSSL_D2I_X509_USES_CONST_CHAR)
    unset(CMAKE_REQUIRED_LIBRARIES)
endif ()
