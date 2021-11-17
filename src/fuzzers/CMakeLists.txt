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

# The bind library is handled a bit hack-ishly since it defaults to linking it
# as static library by default on Linux, but at least on one common distro,
# that static library wasn't compiled with -fPIC and so not usable in the
# shared library we're trying to build.  So instead, the fuzzer executable, not
# the shared lib, links it.
string(REGEX MATCH ".*\\.a$" _have_static_bind_lib "${BIND_LIBRARY}")

macro(ADD_FUZZ_TARGET _name)
    set(_fuzz_target zeek-${_name}-fuzzer)
    set(_fuzz_source ${_name}-fuzzer.cc)

    add_executable(${_fuzz_target} ${_fuzz_source} ${ARGN})

    target_link_libraries(${_fuzz_target} zeek_fuzzer_shared)

    if ( _have_static_bind_lib )
        target_link_libraries(${_fuzz_target} ${BIND_LIBRARY})
    endif ()

    target_link_libraries(${_fuzz_target} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

    if ( DEFINED ZEEK_FUZZING_ENGINE )
        target_link_libraries(${_fuzz_target} ${ZEEK_FUZZING_ENGINE})
    else ()
        target_link_libraries(${_fuzz_target}
                              $<TARGET_OBJECTS:zeek_fuzzer_standalone>)
    endif ()
endmacro ()

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})

add_library(zeek_fuzzer_standalone OBJECT standalone-driver.cc)

add_library(zeek_fuzzer_shared SHARED
            $<TARGET_OBJECTS:zeek_objs>
            ${bro_SUBDIR_LIBS}
            ${bro_PLUGIN_LIBS}
            FuzzBuffer.cc
)

set(zeek_fuzzer_shared_deps)

foreach(_dep ${zeekdeps} )
    if ( "${_dep}" STREQUAL "${BIND_LIBRARY}" )
        if ( NOT _have_static_bind_lib )
            set(zeek_fuzzer_shared_deps ${zeek_fuzzer_shared_deps} ${_dep})
        endif ()
    else ()
        set(zeek_fuzzer_shared_deps ${zeek_fuzzer_shared_deps} ${_dep})
    endif ()
endforeach ()

target_link_libraries(zeek_fuzzer_shared
                      ${zeek_fuzzer_shared_deps}
                      ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

add_fuzz_target(dns)
add_fuzz_target(pop3)
add_fuzz_target(packet)
