message(STATUS "Building Zeek XDP loader")

set(RUST_BIN_NAME "zeek-xdp-loader")
set(RUST_OUT_BIN "${CMAKE_CURRENT_BINARY_DIR}/release/${RUST_BIN_NAME}")

find_program(CARGO_EXECUTABLE cargo REQUIRED)

# TODO: This always builds release, is that okay?
add_custom_command(
    OUTPUT ${RUST_OUT_BIN}
    COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO_EXECUTABLE}
            build --release --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS src/main.rs src/maps.rs
    COMMENT "Compiling Rust Loader..."
    VERBATIM)

add_custom_target(xdp_loader ALL DEPENDS ${RUST_OUT_BIN})

install(PROGRAMS ${RUST_OUT_BIN} DESTINATION bin)
