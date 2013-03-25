# @TEST-SERIALIZE: comm
#
# @TEST-REQUIRES: ifconfig | grep -q -E "inet6 ::1|inet6 addr: ::1"
#
# @TEST-EXEC: btest-bg-run recv bro -b ../recv.bro
# @TEST-EXEC: btest-bg-run send bro -b ../send.bro
# @TEST-EXEC: btest-bg-wait 20
#
# @TEST-EXEC: btest-diff recv/.stdout
# @TEST-EXEC: btest-diff send/.stdout

@TEST-START-FILE send.bro

@load base/frameworks/communication

redef Communication::nodes += {
    ["foo"] = [$host=[::1], $connect=T, $retry=1sec, $events=/my_event/]
};

global my_event: event(s: string);

event remote_connection_handshake_done(p: event_peer)
	{
	print fmt("handshake done with peer: %s", p$host);
	}

event my_event(s: string)
	{
	print fmt("my_event: %s", s);
	terminate();
	}

@TEST-END-FILE

#############

@TEST-START-FILE recv.bro

@load frameworks/communication/listen

redef Communication::listen_ipv6=T;

global my_event: event(s: string);

event remote_connection_handshake_done(p: event_peer)
	{
	print fmt("handshake done with peer: %s", p$host);
	event my_event("hello world");
	}

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@TEST-END-FILE
