# @TEST-DOC: Tests that the IRC::max_dcc_expected_transfers limiting works
#
# @TEST-EXEC: zeek -b -r $TRACES/irc-dcc-state-growth.pcapng %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/irc
@load base/frameworks/notice/weird

# The pcap used for testing has 10 transfers from one host and 20 transfers from another.
# The weird should be generated for the second host.
redef IRC::max_dcc_expected_transfers = 15;
