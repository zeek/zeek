
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro SSH)
	zeek_plugin_cc(SSH.cc Plugin.cc)
	zeek_plugin_bif(types.bif)
	zeek_plugin_bif(events.bif)
	zeek_plugin_pac(ssh.pac ssh-analyzer.pac ssh-protocol.pac consts.pac)
zeek_plugin_end()
