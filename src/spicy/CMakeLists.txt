# See the file "COPYING" in the main distribution directory for copyright.

zeek_add_subdir_library(
    spicy
    INTERNAL_DEPENDENCIES
    ${BIF_BUILD_TARGET}
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
    manager.cc
    file-analyzer.cc
    packet-analyzer.cc
    protocol-analyzer.cc
    runtime-support.cc
    BIFS
    spicy.bif)

# Since HILTI does not support preprocessor macro we do the version replacement in CMake.
#
# TODO(bbannier): Use a static file again once we drop support for Spicy versions before 1.14.0.
if (${SPICY_VERSION_NUMBER} GREATER_EQUAL 11400)
    set(HLTO_LINKER_SCOPE "uint<64>")
else ()
    set(HLTO_LINKER_SCOPE "string")
endif ()
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/scripts/spicy")
configure_file("${PROJECT_SOURCE_DIR}/scripts/spicy/zeek_rt.hlt.in"
               "${CMAKE_BINARY_DIR}/scripts/spicy/zeek_rt.hlt")
configure_file("${PROJECT_SOURCE_DIR}/scripts/spicy/zeek.spicy"
               "${CMAKE_BINARY_DIR}/scripts/spicy/zeek.spicy" COPYONLY)
configure_file("${PROJECT_SOURCE_DIR}/scripts/spicy/zeek_file.spicy"
               "${CMAKE_BINARY_DIR}/scripts/spicy/zeek_file.spicy" COPYONLY)

target_link_libraries(zeek_spicy_obj PRIVATE hilti spicy)
prefer_configured_spicy_include_dirs(zeek_spicy_obj)

set(ZEEK_SPICY_MODULE_PATH "${CMAKE_INSTALL_FULL_LIBDIR}/zeek/spicy" CACHE PATH "")
install(DIRECTORY DESTINATION "${ZEEK_SPICY_MODULE_PATH}")

set(ZEEK_SPICY_LIBRARY_PATH "${CMAKE_INSTALL_FULL_DATADIR}/zeek/spicy" CACHE PATH "")
install(DIRECTORY "${CMAKE_BINARY_DIR}/scripts/spicy/" DESTINATION "${ZEEK_SPICY_LIBRARY_PATH}")

set(ZEEK_SPICY_DATA_PATH "${CMAKE_INSTALL_FULL_DATADIR}/zeek" CACHE PATH "")

add_subdirectory(spicyz)
