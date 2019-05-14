# @TEST-EXEC: zeek -C -r $TRACES/irc-353.pcap %INPUT
# @TEST-EXEC: btest-diff weird.log

event irc_names_info(c: connection, is_orig: bool, c_type: string, channel: string, users: string_set)
	{
	print channel, users;
	}
