# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .

# @TEST-EXEC: btest-bg-run manager  "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b ../master.zeek >../master.out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b ../clone.zeek >../clone.out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b ../clone.zeek >../clone2.out"
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-sort" btest-diff worker-1/err.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-sort" btest-diff worker-2/err.log


# @TEST-START-FILE master.zeek
@load base/frameworks/cluster
redef exit_only_after_terminate = T;

module TestModule;

global t: table[string] of count &backend=Broker::MEMORY;
global s: table[string] of string &backend=Broker::MEMORY;

event add_stuff()
	{
	t["a"] = 5;
	s["a"] = "b";
	print t;
	}

global peers = 0;
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peers;

	if ( peers == 2 )
		schedule 2sec { add_stuff() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	--peers;

	if ( peers == 0 )
		terminate();
	}

# @TEST-END-FILE

# @TEST-START-FILE clone.zeek
@load base/frameworks/cluster
@load base/frameworks/reporter
redef exit_only_after_terminate = T;

module TestModule;

global t: table[count] of count &backend=Broker::MEMORY;
global s: table[string] of count &backend=Broker::MEMORY;

global errlog = open("err.log");

global errors = 0;
event reporter_error(t: time, msg: string, location: string)
	{
	if ( /ProcessStoreEvent/ in msg )
		{
		print errlog, msg;
		++errors;
		}

	if ( errors == 2 )
		terminate();
	}
# @TEST-END-FILE
