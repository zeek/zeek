# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 25

# @TEST-EXEC: btest-diff manager/.stdout

@load base/frameworks/sumstats
@load base/frameworks/cluster

global c = 0;

event do_observe()
	{
	print "do observe", c;
	SumStats::observe("test",
	                  [$str=cat(c)],
	                  [$num=c]
	                  );
	++c;
	schedule 0.1secs { do_observe() };
	}

event zeek_init()
	{
	local r1 = SumStats::Reducer($stream="test",
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=1
	                             );

	SumStats::create([$name="test",
	                  $epoch=10secs,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return 2.0; },
	                  $threshold = 1.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  {
	                  local l = SumStats::get_last(result["test"]);
	                  print "test thresh crossed", l;

	                  if ( l[0]$num == 7 )
	                      terminate();
	                  }
	                 ]);
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node up", name;

	if ( Cluster::node == "worker-1" && name == "manager" )
		schedule 0.1secs { do_observe() };
	}

event Cluster::node_down(name: string, id: string)
	{
	print "node down", name;
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, id: string)
	{
	terminate();
	}
