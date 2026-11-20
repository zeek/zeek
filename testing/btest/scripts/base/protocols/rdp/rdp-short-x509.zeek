# @TEST-DOC: Test weird for overly short RDP certificates
# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-zero-length-x509.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/rdp
@load base/frameworks/notice/weird
