# This tests whether the script-layer can correctly query if a given Broker
# peering originated from the local node or from another node that peered with it.
#
# Can't use this test for -O gen-C++ because of multiple simultaneous
# Zeek runs.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-GROUP: broker
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run client "zeek -b ../client.zeek >out"
# @TEST-EXEC: btest-bg-run server "zeek -b ../server.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff client/out
# @TEST-EXEC: btest-diff server/out

# @TEST-START-FILE client.zeek
redef exit_only_after_terminate = T;

event zeek_init()
	{
	Broker::subscribe("zeek/event/my_topic");
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(ep: Broker::EndpointInfo, msg: string)
	{
	print fmt("peered, this is the outgoing peering: %s",
	    Broker::is_outbound_peering(ep$network$address, ep$network$bound_port));
	print fmt("via Broker::peers(): %s", Broker::peers()[0]$is_outbound);

	Broker::unpeer("127.0.0.1", to_port(getenv("BROKER_PORT")));

	print fmt("after unpeering: %s",
	    Broker::is_outbound_peering(ep$network$address, ep$network$bound_port));
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE server.zeek
redef exit_only_after_terminate = T;

event zeek_init()
	{
	Broker::subscribe("zeek/event/my_topic");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
}

event Broker::peer_added(ep: Broker::EndpointInfo, msg: string)
	{
	print fmt("peered, this is the outgoing peering: %s",
	    Broker::is_outbound_peering(ep$network$address, ep$network$bound_port));
	print fmt("via Broker::peers(): %s", Broker::peers()[0]$is_outbound);
	terminate();
	}
# @TEST-END-FILE
