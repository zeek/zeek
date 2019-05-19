include(TestBigEndian)
test_big_endian(HOST_BIGENDIAN)

include(CheckTypeSize)
check_type_size("unsigned int" SIZEOF_UNSIGNED_INT)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/binpac.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/binpac.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR})
set(binpac_headers
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
    binpac_regex.cc
    ${binpac_headers}
)

if ( ENABLE_SHARED )
  add_library(binpac_lib SHARED ${binpac_lib_SRCS})
  set_target_properties(binpac_lib PROPERTIES
                        SOVERSION ${BINPAC_SOVERSION}
                        VERSION ${BINPAC_VERSION_MAJOR}.${BINPAC_VERSION_MINOR}
                        MACOSX_RPATH true
                        OUTPUT_NAME binpac)
  install(TARGETS binpac_lib DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

if ( ENABLE_STATIC )
  add_library(binpac_static STATIC ${binpac_lib_SRCS})
  set_target_properties(binpac_static PROPERTIES OUTPUT_NAME binpac)
  install(TARGETS binpac_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

if ( ZEEK_ROOT_DIR )
    # Installed in binpac subdir just for organization purposes.
    install(FILES ${binpac_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/binpac)
else ()
    install(FILES ${binpac_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif ()

# This is set to assist superprojects that want to build BinPac
# from source and rely on it as a target
if ( ENABLE_SHARED )
  set(BinPAC_LIBRARY binpac_lib CACHE STRING "BinPAC library" FORCE)
else ()
  set(BinPAC_LIBRARY binpac_static CACHE STRING "BinPAC library" FORCE)
endif ()

set(BinPAC_INCLUDE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    CACHE STRING "BinPAC header directories" FORCE
)
