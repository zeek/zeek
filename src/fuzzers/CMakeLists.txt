########################################################################
## Fuzzing targets

if ( NOT ZEEK_ENABLE_FUZZING )
    return()
endif ()

if ( NOT DEFINED ZEEK_FUZZING_ENGINE AND DEFINED ENV{LIB_FUZZING_ENGINE} )
    set(ZEEK_FUZZING_ENGINE $ENV{LIB_FUZZING_ENGINE} CACHE INTERNAL "" FORCE)
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
        set_target_properties(${_fuzz_target} PROPERTIES LINK_FLAGS
                              ${ZEEK_FUZZING_ENGINE})
    else ()
        target_link_libraries(${_fuzz_target}
                              $<TARGET_OBJECTS:zeek_fuzzer_standalone>)
    endif ()
endmacro ()

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
add_library(zeek_fuzzer_common OBJECT FuzzBuffer.cc)
add_library(zeek_fuzzer_standalone OBJECT standalone-driver.cc)

add_fuzz_target(pop3)
