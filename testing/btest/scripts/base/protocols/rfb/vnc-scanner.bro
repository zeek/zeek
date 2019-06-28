# @TEST-EXEC: zeek -C -r $TRACES/rfb/vnc-scanner.pcap
# @TEST-EXEC: btest-diff rfb.log

@load base/protocols/rfb
