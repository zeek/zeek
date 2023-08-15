spicy_add_analyzer(
    NAME QUIC
    PACKAGE_NAME QUIC
    SOURCES QUIC.spicy QUIC.evt
    SCRIPTS __load__.zeek main.zeek
    CXX_LINK ${CMAKE_CURRENT_BINARY_DIR}/libdecrypt_crypto.a)

add_dependencies(QUIC decrypt_crypto)

find_program(SPICY_CONFIG name spicy-config REQUIRED)
execute_process(
    COMMAND ${SPICY_CONFIG} --include-dirs
    OUTPUT_VARIABLE SPICY_INCLUDE_DIRS)
string(REPLACE " " ";" SPICY_INCLUDE_DIRS ${SPICY_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
add_library(decrypt_crypto STATIC decrypt_crypto.cc)
set_target_properties(
    decrypt_crypto PROPERTIES
    CXX_STANDARD 17
    POSITION_INDEPENDENT_CODE ON)
target_include_directories(decrypt_crypto PRIVATE "${OPENSSL_INCLUDE_DIR}" "${SPICY_INCLUDE_DIRS}")
target_link_libraries(decrypt_crypto ${OpenSSL_LIBRARIES})
