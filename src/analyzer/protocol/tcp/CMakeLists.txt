zeek_add_plugin(
    Zeek TCP
    SOURCES TCP.cc TCP_Endpoint.cc TCP_Reassembler.cc ContentLine.cc Plugin.cc
    BIFS events.bif types.bif functions.bif)
