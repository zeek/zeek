# This tests that an excessively long line is truncated by the contentline
# analyzer

# @TEST-EXEC: zeek -b -C -r $TRACES/contentline-irc-5k-line.pcap %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/irc
@load base/frameworks/notice/weird
