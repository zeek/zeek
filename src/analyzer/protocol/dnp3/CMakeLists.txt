
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek DNP3)
zeek_plugin_cc(DNP3.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(dnp3.pac dnp3-analyzer.pac dnp3-protocol.pac dnp3-objects.pac)
zeek_plugin_end()
