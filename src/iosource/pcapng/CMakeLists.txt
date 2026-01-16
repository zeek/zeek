set(LIGHT_USE_ZSTD OFF CACHE BOOL "" FORCE)
set(LIGHT_USE_ZLIB OFF CACHE BOOL "" FORCE)

add_subdirectory(auxil/LightPcapNg)

zeek_add_plugin(
    Zeek Pcapng
    DEPENDENCIES light_pcapng
    SOURCES Source.cc Plugin.cc)
