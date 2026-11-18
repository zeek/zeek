include(FetchContent)

# FIXME(bbannier): This is to simplify testing,
# realistically we would add a submodule.
set(BENCHMARK_ENABLE_TESTING OFF)
set(FETCHCONTENT_FULLY_DISCONNECTED OFF) # DO NOT MERGE: override CI setting.
FetchContent_Declare(
    benchmark GIT_REPOSITORY https://github.com/google/benchmark GIT_TAG v1.10.0
    # FIND_PACKAGE_ARGS # Requires cmake-3.24, but allows using system dep.
)
FetchContent_MakeAvailable(benchmark)

add_executable(bench-protocol bench.cc)
zeek_link_lib(bench-protocol)
target_link_libraries(bench-protocol PRIVATE benchmark::benchmark benchmark::benchmark_main)
