# @TEST-EXEC: bro -b -r $TRACES/dns-session.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/conn
@load base/protocols/dns

event connection_state_remove(c: connection)
	{
    print c;
	}