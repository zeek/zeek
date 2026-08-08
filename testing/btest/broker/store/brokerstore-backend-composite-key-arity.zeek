# @TEST-DOC: A composite store index whose arity differs between nodes is rejected without reading past the received key.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
# @TEST-EXEC: btest-bg-run manager  "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b ../worker.zeek"
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff worker-1/result.log

# @TEST-START-FILE manager.zeek
@load base/frameworks/cluster
redef exit_only_after_terminate = T;

module TestModule;

global values: table[string, count] of count &backend=Broker::MEMORY;

event add_value()
	{
	values["key", 1] = 42;
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	schedule 1sec { add_value() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
# @TEST-END-FILE

# @TEST-START-FILE worker.zeek
@load base/frameworks/cluster
@load base/frameworks/reporter
redef exit_only_after_terminate = T;

module TestModule;

# The remote key has two components, while this receiver expects three.
global values: table[string, count, count] of count &backend=Broker::MEMORY;
global result = open("result.log");

event reporter_error(t: time, msg: string, location: string)
	{
	if ( /index type doesn't match table/ !in msg )
		return;

	print result, fmt("%s; table-size=%d", msg, |values|);
	terminate();
	}
# @TEST-END-FILE
