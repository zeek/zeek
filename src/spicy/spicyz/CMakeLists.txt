# See the file "COPYING" in the main distribution directory for copyright.

configure_file(config.h.in config.h)

add_executable(spicyz driver.cc glue-compiler.cc main.cc)
target_compile_options(spicyz PRIVATE "-Wall")
target_include_directories(spicyz PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(spicyz PRIVATE hilti spicy)

install(TARGETS spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})
