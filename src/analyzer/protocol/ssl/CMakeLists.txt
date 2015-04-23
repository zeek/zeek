
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro SSL)
bro_plugin_cc(SSL.cc DTLS.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(tls-handshake.pac tls-handshake-protocol.pac tls-handshake-analyzer.pac ssl-defs.pac
	proc-client-hello.pac
	proc-server-hello.pac
	proc-certificate.pac
)
bro_plugin_pac(ssl.pac ssl-dtls-analyzer.pac ssl-analyzer.pac ssl-dtls-protocol.pac ssl-protocol.pac ssl-defs.pac
	proc-client-hello.pac
    proc-server-hello.pac
	proc-certificate.pac
)
bro_plugin_pac(dtls.pac ssl-dtls-analyzer.pac dtls-analyzer.pac ssl-dtls-protocol.pac dtls-protocol.pac ssl-defs.pac)
bro_plugin_end()
