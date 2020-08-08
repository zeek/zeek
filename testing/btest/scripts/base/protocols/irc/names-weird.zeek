# @TEST-EXEC: zeek -b -C -r $TRACES/irc-353.pcap %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/irc
@load base/frameworks/notice/weird

event irc_names_info(c: connection, is_orig: bool, c_type: string, channel: string, users: string_set)
	{
	print channel, users;
	}
