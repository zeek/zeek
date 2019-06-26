include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek PE)
zeek_plugin_cc(PE.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(
  pe.pac
  pe-analyzer.pac
  pe-file-headers.pac
  pe-file-idata.pac
  pe-file.pac
  pe-file-types.pac
)
zeek_plugin_end()
