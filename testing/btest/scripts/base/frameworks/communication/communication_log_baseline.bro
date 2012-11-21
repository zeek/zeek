# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run receiver bro -b ../receiver.bro
# @TEST-EXEC: btest-bg-run sender   bro -b ../sender.bro
# @TEST-EXEC: btest-bg-wait -k 10
#
# Don't diff the receiver log just because port is always going to change
# @TEST-EXEC: egrep -v 'CPU|bytes|pid|socket buffer size' sender/communication.log >send.log
# @TEST-EXEC: btest-diff send.log

@TEST-START-FILE sender.bro

@load base/frameworks/communication/main

redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $events = /NOTHING/, $connect=T]
};

event remote_connection_handshake_done(p: event_peer)
	{
	terminate_communication();
	}

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@TEST-END-FILE

#############

@TEST-START-FILE receiver.bro

@load frameworks/communication/listen

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@TEST-END-FILE
