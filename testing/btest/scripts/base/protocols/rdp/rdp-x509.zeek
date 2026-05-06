# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-x509.pcap %INPUT
# @TEST-EXEC: btest-diff rdp.log
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/rdp
@load base/files/x509
