# @TEST-DOC: Demo for Cluster::Table::publish_new_element()
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-simple.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run logger "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=logger zeek -b ../other.zeek"
# @TEST-EXEC: btest-bg-run proxy "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy zeek -b ../other.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../other.zeek"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../other.zeek"
#
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff manager/.stdout

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap

@load base/frameworks/cluster/table

module Test;

export {
	global a_set: set[string] &on_change=Cluster::Table::publish_element_new;
}

global nodes_up: set[string];

event go()
	{
	add a_set[Cluster::node];
	}

event done() {

	terminate();

}

event Cluster::node_up(name: string, id: string) &priority=-5
	{
	if ( Cluster::node != "manager" )
		return;

	add nodes_up[name];
	print "nodes_up", |nodes_up|;

	if ( |nodes_up| == |Cluster::nodes| - 1 )
		{
		print("sending go");
			Cluster::publish(Cluster::worker_topic, go);
			Cluster::publish(Cluster::logger_topic, go);
			Cluster::publish(Cluster::proxy_topic, go);

		# Wait for 4 entries to appear in the table from the
		# other nodes.
		when ( |a_set| >= 4 )
			{
			local skeys: vector of string;
			for ( k in a_set )
				skeys += k;

			sort(skeys, strcmp);
			print "sorted_keys", skeys;

			Cluster::publish(Cluster::worker_topic, done);
			Cluster::publish(Cluster::logger_topic, done);
			Cluster::publish(Cluster::proxy_topic, done);
			schedule 100msec { done() };
			}
		timeout ( 5sec )
			{
			print "timeout", a_set;
			Cluster::publish(Cluster::worker_topic, done);
			Cluster::publish(Cluster::logger_topic, done);
			Cluster::publish(Cluster::proxy_topic, done);
			schedule 100msec { done() };
			}

		}
	}
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek
# @TEST-END-FILE

# @TEST-START-FILE other.zeek
@load ./common.zeek
# @TEST-END-FILE
