zeek_add_plugin(Zeek Pcap SOURCES Source.cc Dumper.cc Plugin.cc)

# Treat BIFs as builtin (alternative mode).
bif_target(pcap.bif)
