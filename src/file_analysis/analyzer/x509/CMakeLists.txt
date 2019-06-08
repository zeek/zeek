
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro X509)
zeek_plugin_cc(X509Common.cc X509.cc OCSP.cc Plugin.cc)
zeek_plugin_bif(events.bif types.bif functions.bif ocsp_events.bif)
zeek_plugin_pac(x509-extension.pac x509-signed_certificate_timestamp.pac)
zeek_plugin_end()
