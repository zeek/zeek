include_directories(BEFORE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/include)
include_directories(BEFORE ${CMAKE_BUILD_DIR}/src)

# Convenience function to add benchmark executables.
function (add_benchmark name)
    cmake_parse_arguments(FN_ARGS "" "" "SOURCES" ${ARGN})
    if (NOT FN_ARGS_SOURCES)
        message(FATAL_ERROR "add_benchmark called without any SOURCES")
    endif ()

    set(target_name "zeek-${name}-benchmark")
    add_executable(${target_name} ${FN_ARGS_SOURCES})

    set_target_properties(${target_name} PROPERTIES RUNTIME_OUTPUT_NAME ${name})
    set_target_properties(${target_name} PROPERTIES CXX_EXTENSIONS OFF)
    target_compile_features(${target_name} PRIVATE ${ZEEK_CXX_STD})
    target_link_libraries(${target_name} PRIVATE benchmark)

    # Get link libraries from zeek_exe and re-use. Don't judge.
    get_target_property(zeek_target_libs zeek_exe LINK_LIBRARIES)
    target_link_libraries(${target_name} PRIVATE ${zeek_target_libs})
endfunction ()

add_benchmark(double-to-str SOURCES double-to-str.cc)
add_benchmark(int-count-to-str SOURCES int-count-to-str.cc)
add_benchmark(ip-prefix-as-string SOURCES ip-prefix-as-string.cc)
add_benchmark(odesc SOURCES odesc.cc)
