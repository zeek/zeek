# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run receiver bro -b ../receiver.bro
# @TEST-EXEC: sleep 2
# @TEST-EXEC: btest-bg-run sender   bro -b ../sender.bro
# @TEST-EXEC: btest-bg-wait -k 10
#
# Don't diff the receiver log just because port is always going to change
# @TEST-EXEC: egrep -v 'CPU|bytes|pid|socket buffer size' sender/communication.log >send.log
# @TEST-EXEC: btest-diff send.log

@TEST-START-FILE sender.bro

@load base/frameworks/communication/main

redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $connect=T]
};

event Broker::outgoing_connection_established(peer_address: string,
                                             peer_port: port,
                                             peer_name: string)
	{
	terminate_communication();
	}

event Broker::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string)
	{
	terminate();
	}

@TEST-END-FILE

#############

@TEST-START-FILE receiver.bro

@load frameworks/communication/listen

redef Broker::endpoint_name = "test-receiver";
redef exit_only_after_terminate = T;

event Broker::incoming_connection_broken(peer_name: string)
	{
	terminate();
	}

@TEST-END-FILE
