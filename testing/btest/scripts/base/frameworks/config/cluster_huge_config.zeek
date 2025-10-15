# @TEST-DOC: Create a configuration file with 2000 options. Have worker-1 change all the options and ensure every other node observes them, too.
#
# Options are generated using create-config-module.sh and initialized to 0 or "0".
# Upon zeek_done(), all nodes check the values of the options and count any that
# haven't been updated to 1 or "1".
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_LOGGER1_PORT
# @TEST-PORT: BROKER_LOGGER2_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
# @TEST-PORT: BROKER_WORKER3_PORT
# @TEST-PORT: BROKER_WORKER4_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .

# @TEST-EXEC: chmod +x create-config-module.sh
# @TEST-EXEC: ./create-config-module.sh
#
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek -b %INPUT
# @TEST-EXEC: btest-bg-run logger-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run logger-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-3 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-3 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-4 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-4 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30

# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff logger-1/.stdout
# @TEST-EXEC: btest-diff logger-2/.stdout
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout
# @TEST-EXEC: btest-diff worker-3/.stdout
# @TEST-EXEC: btest-diff worker-4/.stdout

@load base/frameworks/config
@load policy/frameworks/cluster/experimental

redef Log::default_rotation_interval = 0secs;

redef Broker::peer_buffer_size = 8192;

@load ./huge-config

event stop() {
	terminate();
}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

@if ( Cluster::node == "worker-1" )
event tick() {
	Cluster::publish(Cluster::manager_topic, stop);
	schedule 20msec { tick() };
}

event Cluster::Experimental::cluster_started()
	{
	local i = 1;
	while ( i <= 10000 )
		{
		Config::set_value(fmt("option_count_%s", i), 1);
		Config::set_value(fmt("option_string_%s", i), "1");
		++i;
		}

	schedule 2000msec { tick() };
	}
@endif

function option_changed(ID: string, new_value: any, location: string): any
	{
	print "option changed", ID, new_value, location;
	return new_value;
	}

event zeek_init() &priority=5
	{
	Option::set_change_handler("option_count_5000", option_changed, -100);
	Option::set_change_handler("option_string_5000", option_changed, -100);
	Option::set_change_handler("option_count_10000", option_changed, -100);
	Option::set_change_handler("option_string_10000", option_changed, -100);
	}

event zeek_done()
	{
	local i = 1;
	local cstale = 0;
	local sstale = 0;
	while ( i <= 10000 )
		{
		local cname = fmt("option_count_%s", i);
		local sname = fmt("option_string_%s", i);
		local cval = lookup_ID(cname) as count;
		local sval = lookup_ID(sname) as string;

		# Check for the new value. 1 or "1"
		if ( cval != 1 )
			++cstale;

		if ( sval != "1" )
			++sstale;
		++i;
		}

	print fmt("cstale=%d sstale=%d", cstale, sstale);
	}

# @TEST-START-FILE create-config-module.sh
#!/bin/bash
set -eux
out="huge-config.zeek";

echo "export {" >> "$out"
for i in {1..10000}; do
	echo "    # Option $i" >> "$out";
	echo "    option option_count_$i: count = 0;" >> "$out";
	echo "    option option_string_$i: string = \"0\";" >> "$out";
done
echo "}" >> "$out"
# @TEST-END-FILE
