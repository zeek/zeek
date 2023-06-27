# See the file "COPYING" in the main distribution directory for copyright.

configure_file(config.h.in config.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h DESTINATION include/zeek/spicy/spicyz)

add_executable(spicyz driver.cc glue-compiler.cc main.cc)
target_compile_options(spicyz PRIVATE "-Wall")
target_compile_features(spicyz PRIVATE "${ZEEK_CXX_STD}")
set_target_properties(spicyz PROPERTIES CXX_EXTENSIONS OFF)

target_include_directories(spicyz PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(spicyz PRIVATE hilti spicy)
prefer_configured_spicy_include_dirs(spicyz)

install(TARGETS spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})
