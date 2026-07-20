# @TeST-DOC: Tests that DCC commands received by themselves don't trigger errors.
#
# @TEST-EXEC: zeek -b -r $TRACES/irc-dcc-first-command.pcap %INPUT >out 2>err
# @TEST-EXEC: btest-diff err

@load base/protocols/irc
