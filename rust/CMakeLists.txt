# TODO(bbannier): We usually vendor CMake dependencies.
include(FetchContent)

# `FetchContent_MakeAvailable` requires internet access which might be disabled. Explicitly allow it.
set(FETCHCONTENT_FULLY_DISCONNECTED OFF)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_SHALLOW ON
    GIT_TAG v0.6.1)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH zeek-regex-backend/Cargo.toml)

corrosion_experimental_cbindgen(TARGET zeek_regex_backend HEADER_NAME zeek_regex_backend.h)
