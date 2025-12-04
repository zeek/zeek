add_subdirectory(auxil/LightPcapNg)

zeek_add_plugin(
    Zeek PcapNg
    SOURCES Source.cc Plugin.cc)

zeek_get_static_plugin_target(target_name Zeek PcapNg)
target_include_directories(${target_name}
                           PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/auxil/LightPcapNg/include")
target_link_libraries(${target_name} PRIVATE light_pcapng)
