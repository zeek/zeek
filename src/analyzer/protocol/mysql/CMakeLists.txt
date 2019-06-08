
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro MySQL)
	zeek_plugin_cc(MySQL.cc Plugin.cc)
	zeek_plugin_bif(events.bif)
	zeek_plugin_pac(mysql.pac mysql-analyzer.pac mysql-protocol.pac)
zeek_plugin_end()
