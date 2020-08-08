# Test IRC events

# @TEST-EXEC: zeek -b -r $TRACES/irc-dcc-send.trace %INPUT
# @TEST-EXEC: zeek -b -r $TRACES/irc-basic.trace %INPUT
# @TEST-EXEC: zeek -b -r $TRACES/irc-whitespace.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/irc

event irc_privmsg_message(c: connection, is_orig: bool, source: string, target: string, message: string)
	{
	print fmt("%s -> %s: %s", source, target, message);
	}

event irc_quit_message(c: connection, is_orig: bool, nick: string, message: string)
	{
	print fmt("quit: %s (%s)", nick, message);
	}
