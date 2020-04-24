########################################################################
## Fuzzing targets

if ( NOT ZEEK_ENABLE_FUZZERS )
    return()
endif ()

if ( NOT DEFINED ZEEK_FUZZING_ENGINE AND DEFINED ENV{LIB_FUZZING_ENGINE} )
    if ( "$ENV{LIB_FUZZING_ENGINE}" STREQUAL "" )
        # Empty LIB_FUZZING_ENGINE, assume libFuzzer
        set(ZEEK_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE INTERNAL "" FORCE)
    else ()
        STRING(SUBSTRING "$ENV{LIB_FUZZING_ENGINE}" 0 1 _first_char)

        if ( "${_first_char}" STREQUAL "-" OR EXISTS "$ENV{LIB_FUZZING_ENGINE}" )
            # Looks like a linker flag or valid file, use it
            set(ZEEK_FUZZING_ENGINE "$ENV{LIB_FUZZING_ENGINE}" CACHE INTERNAL "" FORCE)
        else ()
            message(WARNING "$ENV{LIB_FUZZING_ENGINE} does not exist, assume libFuzzer")
            set(ZEEK_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE INTERNAL "" FORCE)
        endif ()
    endif ()
endif ()

macro(ADD_FUZZ_TARGET _name)
    set(_fuzz_target zeek-${_name}-fuzzer)
    set(_fuzz_source ${_name}-fuzzer.cc)

    add_executable(${_fuzz_target} ${_fuzz_source} ${ARGN}
                   $<TARGET_OBJECTS:zeek_objs>
                   $<TARGET_OBJECTS:zeek_fuzzer_common>
                   ${zeek_HEADERS}
                   ${bro_SUBDIR_LIBS}
                   ${bro_PLUGIN_LIBS})

    target_link_libraries(${_fuzz_target} ${zeekdeps}
                          ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

    if ( DEFINED ZEEK_FUZZING_ENGINE )
        target_link_libraries(${_fuzz_target} ${ZEEK_FUZZING_ENGINE})
    else ()
        target_link_libraries(${_fuzz_target}
                              $<TARGET_OBJECTS:zeek_fuzzer_standalone>)
    endif ()
endmacro ()

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
add_library(zeek_fuzzer_common OBJECT FuzzBuffer.cc)
add_library(zeek_fuzzer_standalone OBJECT standalone-driver.cc)

add_fuzz_target(pop3)
