# @TEST-EXEC: zeek -b -C -r $TRACES/rfb/vnc-scanner.pcap %INPUT
# @TEST-EXEC: btest-diff rfb.log

@load base/protocols/rfb
