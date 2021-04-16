# This tests a PCAP with a few SIP commands from the Wireshark samples.

# @TEST-EXEC: zeek -b -r $TRACES/sip/sip-junk-before-request.pcap %INPUT
# @TEST-EXEC: btest-diff sip.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/sip
@load base/frameworks/notice/weird
