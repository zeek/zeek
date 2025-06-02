# @TEST-DOC: Smoke test that the seen/smtp mime_end_entity() only runs when Intel::ADDR indicators are loaded and mime_end_entity() runs for a SMTP connection.
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: zeek --parse-only %INPUT
#
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff manager/intel.log

@load base/frameworks/cluster
@load base/frameworks/intel

@load frameworks/intel/seen
@load frameworks/intel/seen/manage-event-groups

@load frameworks/cluster/experimental

redef Log::default_rotation_interval = 0secs;

global addr_indicator = Intel::Item(
	$indicator="1.2.3.4",
	$indicator_type=Intel::ADDR,
	$meta=Intel::MetaData($source="source1"),
);

function make_conn(): connection
	{
	local c = connection(
			$id = conn_id($orig_h=1.1.1.1, $orig_p=1/tcp,
			              $resp_h=2.2.2.2, $resp_p=2/tcp, $proto=6),
			$orig = endpoint($size=1, $state=4, $flow_label=0),
			$resp = endpoint($size=1, $state=4, $flow_label=0),
			$start_time=double_to_time(1747323991.0),
			$duration=1sec,
			$service=set("smtp"),
			$history="ShAdDa",
			$uid="CHhAvVGS1DHFjwGM9",
	);

	c$smtp = SMTP::Info(
		$ts=c$start_time,
		$uid=c$uid,
		$id=c$id,
		$trans_depth=1,
		$path=vector(1.2.3.4)
	);

	c$smtp$x_originating_ip = 1.2.3.5;

	return c;
	}

global current_step = 0;

global do_step: event(step: count);

event publish_do_step(step: count)
	{
	local topic = Cluster::local_node_type() == Cluster::MANAGER ? Cluster::worker_topic : Cluster::manager_topic;
	print fmt("publish do_step(%s) to %s", step, topic);
	Cluster::publish(topic, do_step, step);
	}

# Log Intel::seen_policy() invocations.
#
# The idea here is that if the seen event groups are disabled,
# the Intel::seen_policy() hook isn't invoked at all. So we can
# use that to verify that the corresponding events have actually
# been disabled.
hook Intel::seen_policy(s: Intel::Seen, found: bool)
	{
	print fmt("Intel::seen_policy(%s of %s, %s)",
	          s?$host ? cat(s$host) : s$indicator,
	          s?$host ? "Intel::ADDR" : cat(s$indicator_type),
	          found);
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	print fmt("Intel::match: %s %s", s$indicator, s$indicator_type);
	if ( current_step == 2 )
		event do_step(4);
	}

event do_step(step: count)
	{
	current_step = step;
	print fmt("running do_step(%s)", step);

	switch ( step ) {
	case 1:  # worker
		local c1 = make_conn();
		event mime_end_entity(c1);
		event publish_do_step(2);
		break;
	case 2:  # manager, insert a intel indicator
		Intel::insert(addr_indicator);
		event publish_do_step(3);
		break;
	case 3:  # worker - should have an addr indicator now, match it.
		local c2 = make_conn();
		event mime_end_entity(c2);
		# no publish of step 4, see Intel::match() that drives it
		break;
	case 4:  # manager waits for the match
		Intel::remove(addr_indicator);
		event publish_do_step(5);
		break;
	case 5:  # worker - the ADDR groups are disabled again.
		local c3 = make_conn();
		event mime_end_entity(c3);
		event publish_do_step(6);
		break;
	case 6: # manager, done
		terminate();
		break;
	}
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "worker-1" )
		event do_step(1);
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}

# Output a few internal things for sanity. These aren't testing functionality,
# but nice to have.
module Intel;
event Intel::match_remote(s: Intel::Seen)
	{
	print fmt("Intel::match_remote: %s %s", s$indicator, s$indicator_type);
	}

hook Intel::indicator_inserted(indicator: string, indicator_type: Intel::Type)
	{
	print fmt("Intel::indicator_inserted %s %s", indicator, indicator_type);
	}

hook Intel::indicator_removed(indicator: string, indicator_type: Intel::Type)
	{
	print fmt("Intel::indicator_removed %s %s", indicator, indicator_type);
	}
