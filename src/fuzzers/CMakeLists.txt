########################################################################
## Fuzzing targets

if ( NOT ZEEK_ENABLE_FUZZING )
    return()
endif ()

macro(ADD_FUZZ_TARGET _name)
    set(_fuzz_target zeek_fuzzer_${_name})
    set(_fuzz_source ${_name}.cc)

    add_executable(${_fuzz_target} ${_fuzz_source} ${ARGN}
                   $<TARGET_OBJECTS:zeek_objs>
                   $<TARGET_OBJECTS:zeek_fuzzer_objs>
                   ${zeek_HEADERS}
                   ${bro_SUBDIR_LIBS}
                   ${bro_PLUGIN_LIBS})

    target_link_libraries(${_fuzz_target} ${zeekdeps}
                          ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

    # TODO: Use LIB_FUZZING_ENGINE env. var. if it exists
    set_target_properties(${_fuzz_target} PROPERTIES LINK_FLAGS
                          "-fsanitize=fuzzer")
endmacro ()

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
add_library(zeek_fuzzer_objs OBJECT FuzzBuffer.cc)

add_fuzz_target(pop3)
