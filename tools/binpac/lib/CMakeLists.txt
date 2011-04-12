include(TestBigEndian)
test_big_endian(HOST_BIGENDIAN)

include(CheckTypeSize)
check_type_size("unsigned int" SIZEOF_UNSIGNED_INT)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/binpac.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/binpac.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR})
set(binpac_headers
    binpac.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/binpac.h
    binpac_analyzer.h
    binpac_buffer.h
    binpac_bytestring.h
    binpac_exception.h
    binpac_regex.h
)

set(binpac_lib_SRCS
    binpac_buffer.cc
    binpac_bytestring.cc
    ${binpac_headers}
)

add_library(binpac_lib STATIC ${binpac_lib_SRCS})

set_target_properties(binpac_lib PROPERTIES OUTPUT_NAME binpac)

if (NOT BinPAC_SKIP_INSTALL)
    install(TARGETS binpac_lib DESTINATION lib)
    install(FILES
                ${binpac_headers}
            DESTINATION
                include
    )
endif ()

# This is set to assist superprojects that want to build BinPac
# from source and rely on it as a target
set(BinPAC_LIBRARY binpac_lib
    CACHE STRING "BinPAC static library" FORCE
)

set(BinPAC_INCLUDE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    CACHE STRING "BinPAC header directories" FORCE
)
