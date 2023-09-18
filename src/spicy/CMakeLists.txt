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

target_link_libraries(zeek_spicy_obj PRIVATE hilti spicy)
prefer_configured_spicy_include_dirs(zeek_spicy_obj)

set(ZEEK_SPICY_MODULE_PATH "${CMAKE_INSTALL_FULL_LIBDIR}/zeek/spicy" CACHE PATH "")
install(DIRECTORY DESTINATION "${ZEEK_SPICY_MODULE_PATH}")

set(ZEEK_SPICY_LIBRARY_PATH "${CMAKE_INSTALL_FULL_DATADIR}/zeek/spicy" CACHE PATH "")
install(DIRECTORY "${PROJECT_SOURCE_DIR}/scripts/spicy/" DESTINATION "${ZEEK_SPICY_LIBRARY_PATH}")

set(ZEEK_SPICY_DATA_PATH "${CMAKE_INSTALL_FULL_DATADIR}/zeek" CACHE PATH "")

add_subdirectory(spicyz)
