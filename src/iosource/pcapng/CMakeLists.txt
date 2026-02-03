set(LIGHT_USE_ZSTD OFF CACHE BOOL "" FORCE)
set(LIGHT_USE_ZLIB OFF CACHE BOOL "" FORCE)

set(_build_shared ${BUILD_SHARED_LIBS})
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(auxil/LightPcapNg EXCLUDE_FROM_ALL)
set(BUILD_SHARED_LIBS ${_build_shared})

zeek_add_plugin(
    Zeek Pcapng
    DEPENDENCIES light_pcapng
    SOURCES Source.cc Plugin.cc)
