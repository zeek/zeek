# See the file "COPYING" in the main distribution directory for copyright.

configure_file(config.h.in config.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h DESTINATION include/zeek/spicy/spicyz)

add_executable(spicyz driver.cc glue-compiler.cc main.cc zeek-version.cc)
target_compile_options(spicyz PRIVATE "-Wall")
target_compile_features(spicyz PRIVATE "${ZEEK_CXX_STD}")
set_target_properties(spicyz PROPERTIES CXX_EXTENSIONS OFF)

target_include_directories(spicyz PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (BINARY_PACKAGING_MODE)
    # Ensure we link against the HILTI/Spicy toolchain libraries (should be
    # default, but isn't set here for some reason).
    set(HAVE_TOOLCHAIN ON)

    hilti_link_object_libraries_in_tree(spicyz PRIVATE)
    spicy_link_object_libraries_in_tree(spicyz PRIVATE)
else ()
    hilti_link_libraries_in_tree(spicyz PRIVATE)
    spicy_link_libraries_in_tree(spicyz PRIVATE)
endif ()

prefer_configured_spicy_include_dirs(spicyz)

install(TARGETS spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})
