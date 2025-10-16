zeek_add_plugin(
    Zeek Pcap
    SOURCES PcapSource.cc PcapDumper.cc Plugin.cc)

# Treat BIFs as builtin (alternative mode).
bif_target(pcap.bif)
