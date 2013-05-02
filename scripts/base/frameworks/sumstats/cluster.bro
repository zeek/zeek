##! This implements transparent cluster support for the SumStats framework.
##! Do not load this file directly.  It's only meant to be loaded automatically
##! and will be depending on if the cluster framework has been enabled.
##! The goal of this script is to make sumstats calculation completely and
##! transparently automated when running on a cluster.

@load base/frameworks/cluster
@load ./main

module SumStats;

export {
	## Allows a user to decide how large of result groups the workers should transmit
	## values for cluster stats aggregation.
	const cluster_send_in_groups_of = 50 &redef;

	## The percent of the full threshold value that needs to be met on a single worker
	## for that worker to send the value to its manager in order for it to request a
	## global view for that value.  There is no requirement that the manager requests
	## a global view for the key since it may opt not to if it requested a global view
	## for the key recently.
	const cluster_request_global_view_percent = 0.2 &redef;

	## This is to deal with intermediate update overload.  A manager will only allow
	## this many intermediate update requests to the workers to be inflight at any
	## given time.  Requested intermediate updates are currently thrown out and not
	## performed.  In practice this should hopefully have a minimal effect.
	const max_outstanding_global_views = 10 &redef;

	## Intermediate updates can cause overload situations on very large clusters. This
	## option may help reduce load and correct intermittent problems. The goal for this
	## option is also meant to be temporary.
	const enable_intermediate_updates = T &redef;

	## Event sent by the manager in a cluster to initiate the collection of values for
	## a sumstat.
	global cluster_ss_request: event(uid: string, ssid: string);

	## Event sent by nodes that are collecting sumstats after receiving a request for
	## the sumstat from the manager.
	global cluster_ss_response: event(uid: string, ssid: string, data: ResultTable, done: bool);

	## This event is sent by the manager in a cluster to initiate the collection of
	## a single key value from a sumstat.  It's typically used to get intermediate
	## updates before the break interval triggers to speed detection of a value
	## crossing a threshold.
	global cluster_key_request: event(uid: string, ssid: string, key: Key);

	## This event is sent by nodes in response to a
	## :bro:id:`SumStats::cluster_key_request` event.
	global cluster_key_response: event(uid: string, ssid: string, key: Key, result: Result);

	## This is sent by workers to indicate that they crossed the percent
	## of the current threshold by the percentage defined globally in
	## :bro:id:`SumStats::cluster_request_global_view_percent`
	global cluster_key_intermediate_response: event(ssid: string, key: SumStats::Key);

	## This event is scheduled internally on workers to send result chunks.
	global send_data: event(uid: string, ssid: string, data: ResultTable);

	## This event is generated when a threshold is crossed.
	global cluster_threshold_crossed: event(ssid: string, key: SumStats::Key, thold: Thresholding);
}

# Add events to the cluster framework to make this work.
redef Cluster::manager2worker_events += /SumStats::cluster_(ss_request|key_request|threshold_crossed)/;
redef Cluster::manager2worker_events += /SumStats::thresholds_reset/;
redef Cluster::worker2manager_events += /SumStats::cluster_(ss_response|key_response|key_intermediate_response)/;

@if ( Cluster::local_node_type() != Cluster::MANAGER )
# This variable is maintained to know what keys have recently sent as
# intermediate updates so they don't overwhelm their manager. The count that is
# yielded is the number of times the percentage threshold has been crossed and
# an intermediate result has been received.
global recent_global_view_keys: table[string, Key] of count &create_expire=1min &default=0;

event bro_init() &priority=-100
	{
	# The manager is the only host allowed to track these.
	stats_store = table();
	reducer_store = table();
	}

# This is done on all non-manager node types in the event that a sumstat is
# being collected somewhere other than a worker.
function data_added(ss: SumStat, key: Key, result: Result)
	{
	# If an intermediate update for this value was sent recently, don't send
	# it again.
	if ( [ss$id, key] in recent_global_view_keys )
		return;

	# If val is 5 and global view % is 0.1 (10%), pct_val will be 50.  If that
	# crosses the full threshold then it's a candidate to send as an
	# intermediate update.
	if ( enable_intermediate_updates &&
	     check_thresholds(ss, key, result, cluster_request_global_view_percent) )
		{
		# kick off intermediate update
		event SumStats::cluster_key_intermediate_response(ss$id, copy(key));
		++recent_global_view_keys[ss$id, key];
		}
	}

event SumStats::send_data(uid: string, ssid: string, data: ResultTable)
	{
	#print fmt("WORKER %s: sending data for uid %s...", Cluster::node, uid);

	local local_data: ResultTable = table();
	local num_added = 0;
	for ( key in data )
		{
		local_data[key] = data[key];
		delete data[key];

		# Only send cluster_send_in_groups_of at a time.  Queue another
		# event to send the next group.
		if ( cluster_send_in_groups_of == ++num_added )
			break;
		}

	local done = F;
	# If data is empty, this sumstat is done.
	if ( |data| == 0 )
		done = T;

	event SumStats::cluster_ss_response(uid, ssid, copy(local_data), done);
	if ( ! done )
		schedule 0.01 sec { SumStats::send_data(uid, ssid, data) };
	}

event SumStats::cluster_ss_request(uid: string, ssid: string)
	{
	#print fmt("WORKER %s: received the cluster_ss_request event for %s.", Cluster::node, id);

	# Initiate sending all of the data for the requested stats.
	if ( ssid in result_store )
		event SumStats::send_data(uid, ssid, result_store[ssid]);
	else
		event SumStats::send_data(uid, ssid, table());

	# Lookup the actual sumstats and reset it, the reference to the data
	# currently stored will be maintained internally by the send_data event.
	if ( ssid in stats_store )
		reset(stats_store[ssid]);
	}

event SumStats::cluster_key_request(uid: string, ssid: string, key: Key)
	{
	if ( ssid in result_store && key in result_store[ssid] )
		{
		#print fmt("WORKER %s: received the cluster_key_request event for %s=%s.", Cluster::node, key2str(key), data);
		event SumStats::cluster_key_response(uid, ssid, key, copy(result_store[ssid][key]));
		}
	else
		{
		# We need to send an empty response if we don't have the data so that the manager
		# can know that it heard back from all of the workers.
		event SumStats::cluster_key_response(uid, ssid, key, table());
		}
	}

event SumStats::cluster_threshold_crossed(ssid: string, key: SumStats::Key, thold: Thresholding)
	{
	if ( ssid !in threshold_tracker )
		threshold_tracker[ssid] = table();

	threshold_tracker[ssid][key] = thold;
	}

event SumStats::thresholds_reset(ssid: string)
	{
	threshold_tracker[ssid] = table();
	}

@endif


@if ( Cluster::local_node_type() == Cluster::MANAGER )

# This variable is maintained by manager nodes as they collect and aggregate
# results.
# Index on a uid.
global stats_results: table[string] of ResultTable &read_expire=1min;

# This variable is maintained by manager nodes to track how many "dones" they
# collected per collection unique id.  Once the number of results for a uid
# matches the number of peer nodes that results should be coming from, the
# result is written out and deleted from here.
# Indexed on a uid.
# TODO: add an &expire_func in case not all results are received.
global done_with: table[string] of count &read_expire=1min &default=0;

# This variable is maintained by managers to track intermediate responses as
# they are getting a global view for a certain key.
# Indexed on a uid.
global key_requests: table[string] of Result &read_expire=1min;

# This variable is maintained by managers to prevent overwhelming communication due
# to too many intermediate updates.  Each sumstat is tracked separately so that
# one won't overwhelm and degrade other quieter sumstats.
# Indexed on a sumstat id.
global outstanding_global_views: table[string] of count &default=0;

const zero_time = double_to_time(0.0);
# Managers handle logging.
event SumStats::finish_epoch(ss: SumStat)
	{
	if ( network_time() > zero_time )
		{
		#print fmt("%.6f MANAGER: breaking %s sumstat for %s sumstat", network_time(), ss$name, ss$id);
		local uid = unique_id("");

		if ( uid in stats_results )
			delete stats_results[uid];
		stats_results[uid] = table();

		# Request data from peers.
		event SumStats::cluster_ss_request(uid, ss$id);
		}

	# Schedule the next finish_epoch event.
	schedule ss$epoch { SumStats::finish_epoch(ss) };
	}

# This is unlikely to be called often, but it's here in
# case there are sumstats being collected by managers.
function data_added(ss: SumStat, key: Key, result: Result)
	{
	if ( check_thresholds(ss, key, result, 1.0) )
		{
		threshold_crossed(ss, key, result);
		event SumStats::cluster_threshold_crossed(ss$id, key, threshold_tracker[ss$id][key]);
		}
	}

event SumStats::cluster_key_response(uid: string, ssid: string, key: Key, result: Result)
	{
	#print fmt("%0.6f MANAGER: receiving key data from %s - %s=%s", network_time(), get_event_peer()$descr, key2str(key), result);

	# We only want to try and do a value merge if there are actually measured datapoints
	# in the Result.
	if ( uid in key_requests )
		key_requests[uid] = compose_results(key_requests[uid], result);
	else
		key_requests[uid] = result;

	# Mark that a worker is done.
	++done_with[uid];

	#print fmt("worker_count:%d :: done_with:%d", Cluster::worker_count, done_with[uid]);
	if ( Cluster::worker_count == done_with[uid] )
		{
		local ss = stats_store[ssid];
		local ir = key_requests[uid];
		if ( check_thresholds(ss, key, ir, 1.0) )
			{
			threshold_crossed(ss, key, ir);
			event SumStats::cluster_threshold_crossed(ss$id, key, threshold_tracker[ss$id][key]);
			}

		delete done_with[uid];
		delete key_requests[uid];
		# Check that there is an outstanding view before subtracting.
		if ( outstanding_global_views[ssid] > 0 )
			--outstanding_global_views[ssid];
		}
	}

# Managers handle intermediate updates here.
event SumStats::cluster_key_intermediate_response(ssid: string, key: Key)
	{
	#print fmt("MANAGER: receiving intermediate key data from %s", get_event_peer()$descr);
	#print fmt("MANAGER: requesting key data for %s", key2str(key));

	if ( ssid in outstanding_global_views &&
	     |outstanding_global_views[ssid]| > max_outstanding_global_views )
		{
		# Don't do this intermediate update.  Perhaps at some point in the future
		# we will queue and randomly select from these ignored intermediate
		# update requests.
		return;
		}

	++outstanding_global_views[ssid];

	local uid = unique_id("");
	event SumStats::cluster_key_request(uid, ssid, key);
	}

event SumStats::cluster_ss_response(uid: string, ssid: string, data: ResultTable, done: bool)
	{
	#print fmt("MANAGER: receiving results from %s", get_event_peer()$descr);

	# Mark another worker as being "done" for this uid.
	if ( done )
		++done_with[uid];

	local local_data = stats_results[uid];
	local ss = stats_store[ssid];

	for ( key in data )
		{
		if ( key in local_data )
			local_data[key] = compose_results(local_data[key], data[key]);
		else
			local_data[key] = data[key];

		# If a stat is done being collected, thresholds for each key
		# need to be checked so we're doing it here to avoid doubly
		# iterating over each key.
		if ( Cluster::worker_count == done_with[uid] )
			{
			if ( check_thresholds(ss, key, local_data[key], 1.0) )
				{
				threshold_crossed(ss, key, local_data[key]);
				event SumStats::cluster_threshold_crossed(ss$id, key, threshold_tracker[ss$id][key]);
				}
			}
		}

	# If the data has been collected from all peers, we are done and ready to finish.
	if ( Cluster::worker_count == done_with[uid] )
		{
		if ( ss?$epoch_finished )
			ss$epoch_finished(local_data);

		# Clean up
		delete stats_results[uid];
		delete done_with[uid];
		# Not sure I need to reset the sumstat on the manager.
		reset(ss);
		}
	}

event remote_connection_handshake_done(p: event_peer) &priority=5
	{
	send_id(p, "SumStats::stats_store");
	send_id(p, "SumStats::reducer_store");
	}
@endif
