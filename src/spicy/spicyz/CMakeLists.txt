# See the file "COPYING" in the main distribution directory for copyright.

configure_file(config.h.in config.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h driver.h glue-compiler.h zeek-version.h
        DESTINATION include/zeek/spicy/spicyz)

set(SPICYZ_DRIVER_SOURCES driver.cc glue-compiler.cc zeek-version.cc)

add_executable(spicyz main.cc)
target_compile_features(spicyz PRIVATE "${ZEEK_CXX_STD}")
set_target_properties(spicyz PROPERTIES CXX_EXTENSIONS OFF)

# SHARED library so external consumers do not need to resolve transitive
# HILTI/Spicy dependencies. On Windows no symbols are exported yet so MSVC
# would not produce a usable import library; compile the driver sources
# directly into the executable instead.
if (WIN32)
    target_sources(spicyz PRIVATE ${SPICYZ_DRIVER_SOURCES})
    target_include_directories(spicyz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                              ${CMAKE_CURRENT_BINARY_DIR})
    prefer_configured_spicy_include_dirs(spicyz)
    set(_spicyz_driver spicyz)
    set(_spicyz_vis PRIVATE)
else ()
    add_library(spicyz-driver SHARED ${SPICYZ_DRIVER_SOURCES})
    target_compile_features(spicyz-driver PUBLIC "${ZEEK_CXX_STD}")
    set_target_properties(spicyz-driver PROPERTIES CXX_EXTENSIONS OFF)
    target_include_directories(spicyz-driver PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                                                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
    prefer_configured_spicy_include_dirs(spicyz-driver)
    target_link_libraries(spicyz PRIVATE spicyz-driver)
    install(TARGETS spicyz-driver LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
    set(_spicyz_driver spicyz-driver)
    set(_spicyz_vis PUBLIC)
endif ()

# We do not compile spicyz's own sources with sanitizers — the global linker
# flags ensure the ASan runtime is available for the sanitized HILTI runtime
# objects in libhilti.so.

if (SPICY_ROOT_DIR)
    target_link_libraries(${_spicyz_driver} ${_spicyz_vis} hilti spicy)
else ()
    if (BINARY_PACKAGING_MODE)
        # Ensure we link against the HILTI/Spicy toolchain libraries (should be
        # default, but isn't set here for some reason).
        set(HAVE_TOOLCHAIN ON)

        hilti_link_object_libraries_in_tree(${_spicyz_driver} ${_spicyz_vis})
        spicy_link_object_libraries_in_tree(${_spicyz_driver} ${_spicyz_vis})
    else ()
        hilti_link_libraries_in_tree(${_spicyz_driver} ${_spicyz_vis})
        spicy_link_libraries_in_tree(${_spicyz_driver} ${_spicyz_vis})
    endif ()
endif ()

install(TARGETS spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})
