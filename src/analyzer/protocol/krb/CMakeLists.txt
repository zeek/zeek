include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro KRB)
zeek_plugin_cc(Plugin.cc)
zeek_plugin_cc(KRB.cc)
zeek_plugin_cc(KRB_TCP.cc)
zeek_plugin_bif(types.bif)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(krb.pac krb-protocol.pac krb-analyzer.pac
	krb-asn1.pac
	krb-defs.pac
	krb-types.pac
	krb-padata.pac
	../asn1/asn1.pac
)
zeek_plugin_pac(krb_TCP.pac krb-protocol.pac krb-analyzer.pac
	krb-asn1.pac
	krb-defs.pac
    krb-types.pac
	krb-padata.pac
	../asn1/asn1.pac
)
zeek_plugin_end()
