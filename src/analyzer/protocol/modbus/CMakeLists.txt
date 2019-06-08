
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro Modbus)
zeek_plugin_cc(Modbus.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(modbus.pac modbus-analyzer.pac modbus-protocol.pac)
zeek_plugin_end()
