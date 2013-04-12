##! This implements transparent cluster support for the metrics framework.
##! Do not load this file directly.  It's only meant to be loaded automatically
##! and will be depending on if the cluster framework has been enabled.
##! The goal of this script is to make metric calculation completely and
##! transparently automated when running on a cluster.

@load base/frameworks/cluster
@load ./main

module Measurement;

export {
	## Allows a user to decide how large of result groups the 
	## workers should transmit values for cluster metric aggregation.
	const cluster_send_in_groups_of = 50 &redef;
	
	## The percent of the full threshold value that needs to be met 
	## on a single worker for that worker to send the value to its manager in
	## order for it to request a global view for that value.  There is no
	## requirement that the manager requests a global view for the key
	## since it may opt not to if it requested a global view for the key
	## recently.
	const cluster_request_global_view_percent = 0.2 &redef;

	## This is to deal with intermediate update overload.  A manager will only allow
	## this many intermediate update requests to the workers to be inflight at 
	## any given time.  Requested intermediate updates are currently thrown out
	## and not performed.  In practice this should hopefully have a minimal effect.
	const max_outstanding_global_views = 10 &redef;

	## Intermediate updates can cause overload situations on very large clusters.
	## This option may help reduce load and correct intermittent problems.
	## The goal for this option is also meant to be temporary.
	const enable_intermediate_updates = T &redef;

	## Event sent by the manager in a cluster to initiate the 
	## collection of metrics values for a measurement.
	global cluster_measurement_request: event(uid: string, mid: string);

	## Event sent by nodes that are collecting metrics after receiving
	## a request for the metric measurement from the manager.
	global cluster_measurement_response: event(uid: string, mid: string, data: ResultTable, done: bool);

	## This event is sent by the manager in a cluster to initiate the
	## collection of a single key value from a measurement.  It's typically
	## used to get intermediate updates before the break interval triggers
	## to speed detection of a value crossing a threshold.
	global cluster_key_request: event(uid: string, mid: string, key: Key);

	## This event is sent by nodes in response to a 
	## :bro:id:`Measurement::cluster_key_request` event.
	global cluster_key_response: event(uid: string, mid: string, key: Key, result: Result);

	## This is sent by workers to indicate that they crossed the percent of the 
	## current threshold by the percentage defined globally in 
	## :bro:id:`Measurement::cluster_request_global_view_percent`
	global cluster_key_intermediate_response: event(mid: string, key: Measurement::Key);

	## This event is scheduled internally on workers to send result chunks.
	global send_data: event(uid: string, mid: string, data: ResultTable);
}

# Add events to the cluster framework to make this work.
redef Cluster::manager2worker_events += /Measurement::cluster_(measurement_request|key_request)/;
redef Cluster::manager2worker_events += /Measurement::new_measurement/;
redef Cluster::worker2manager_events += /Measurement::cluster_(measurement_response|key_response|key_intermediate_response)/;

@if ( Cluster::local_node_type() != Cluster::MANAGER )
# This variable is maintained to know what keys have recently sent as 
# intermediate updates so they don't overwhelm their manager. The count that is
# yielded is the number of times the percentage threshold has been crossed and
# an intermediate result has been received.
global recent_global_view_keys: table[string, Key] of count &create_expire=1min &default=0;

event bro_init() &priority=-100
	{
	# The manager is the only host allowed to track these.
	measurement_store = table();
	reducer_store = table();
	}

# This is done on all non-manager node types in the event that a metric is 
# being collected somewhere other than a worker.
function data_added(m: Measurement, key: Key, result: Result)
	{
	# If an intermediate update for this value was sent recently, don't send
	# it again.
	if ( [m$id, key] in recent_global_view_keys )
		return;

	# If val is 5 and global view % is 0.1 (10%), pct_val will be 50.  If that
	# crosses the full threshold then it's a candidate to send as an 
	# intermediate update.
	if ( enable_intermediate_updates && 
	     check_thresholds(m, key, result, cluster_request_global_view_percent) )
		{
		# kick off intermediate update
		event Measurement::cluster_key_intermediate_response(m$id, key);
		++recent_global_view_keys[m$id, key];
		}
	}

event Measurement::send_data(uid: string, mid: string, data: ResultTable)
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
	# If data is empty, this metric is done.
	if ( |data| == 0 )
		done = T;
	
	event Measurement::cluster_measurement_response(uid, mid, local_data, done);
	if ( ! done )
		schedule 0.01 sec { Measurement::send_data(uid, mid, data) };
	}

event Measurement::cluster_measurement_request(uid: string, mid: string)
	{
	#print fmt("WORKER %s: received the cluster_measurement_request event for %s.", Cluster::node, id);
	
	# Initiate sending all of the data for the requested measurement.
	if ( mid in result_store )
		event Measurement::send_data(uid, mid, result_store[mid]);
	else
		event Measurement::send_data(uid, mid, table());

	# Lookup the actual measurement and reset it, the reference to the data
	# currently stored will be maintained internally by the send_data event.
	if ( mid in measurement_store )
		reset(measurement_store[mid]);
	}
	
event Measurement::cluster_key_request(uid: string, mid: string, key: Key)
	{
	if ( mid in result_store && key in result_store[mid] )
		{
		#print fmt("WORKER %s: received the cluster_key_request event for %s=%s.", Cluster::node, key2str(key), data);
		event Measurement::cluster_key_response(uid, mid, key, result_store[mid][key]);
		}
	else
		{
		# We need to send an empty response if we don't have the data so that the manager
		# can know that it heard back from all of the workers.
		event Measurement::cluster_key_response(uid, mid, key, table());
		}
	}

@endif


@if ( Cluster::local_node_type() == Cluster::MANAGER )

# This variable is maintained by manager nodes as they collect and aggregate 
# results.  
# Index on a uid.
global measurement_results: table[string] of ResultTable &read_expire=1min;

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
# to too many intermediate updates.  Each measurement is tracked separately so that 
# one won't overwhelm and degrade other quieter measurements. 
# Indexed on a measurement id.
global outstanding_global_views: table[string] of count &default=0;

const zero_time = double_to_time(0.0);
# Managers handle logging.
event Measurement::finish_epoch(m: Measurement)
	{
	if ( network_time() > zero_time )
		{
		#print fmt("%.6f MANAGER: breaking %s measurement for %s metric", network_time(), measurement$name, measurement$id);
		local uid = unique_id("");
		
		if ( uid in measurement_results )
			delete measurement_results[uid];
		measurement_results[uid] = table();
		
		# Request data from peers.
		event Measurement::cluster_measurement_request(uid, m$id);
		}

	# Schedule the next finish_epoch event.
	schedule m$epoch { Measurement::finish_epoch(m) };
	}

# This is unlikely to be called often, but it's here in case there are measurements
# being collected by managers.
function data_added(m: Measurement, key: Key, result: Result)
	{
	if ( check_thresholds(m, key, result, 1.0) )
		threshold_crossed(m, key, result);
	}
	
event Measurement::cluster_key_response(uid: string, mid: string, key: Key, result: Result)
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
		local m = measurement_store[mid];
		local ir = key_requests[uid];
		if ( check_thresholds(m, key, ir, 1.0) )
			threshold_crossed(m, key, ir);

		delete done_with[uid];
		delete key_requests[uid];
		# Check that there is an outstanding view before subtracting.
		if ( outstanding_global_views[mid] > 0 )
			--outstanding_global_views[mid];
		}
	}

# Managers handle intermediate updates here.
event Measurement::cluster_key_intermediate_response(mid: string, key: Key)
	{
	#print fmt("MANAGER: receiving intermediate key data from %s", get_event_peer()$descr);
	#print fmt("MANAGER: requesting key data for %s", key2str(key));

	if ( mid in outstanding_global_views &&
	     |outstanding_global_views[mid]| > max_outstanding_global_views )
		{
		# Don't do this intermediate update.  Perhaps at some point in the future 
		# we will queue and randomly select from these ignored intermediate
		# update requests.
		return;
		}

	++outstanding_global_views[mid];

	local uid = unique_id("");
	event Measurement::cluster_key_request(uid, mid, key);
	}

event Measurement::cluster_measurement_response(uid: string, mid: string, data: ResultTable, done: bool)
	{
	#print fmt("MANAGER: receiving results from %s", get_event_peer()$descr);

	# Mark another worker as being "done" for this uid.
	if ( done )
		++done_with[uid];

	local local_data = measurement_results[uid];
	local m = measurement_store[mid];

	for ( key in data )
		{
		if ( key in local_data )
			local_data[key] = compose_results(local_data[key], data[key]);
		else
			local_data[key] = data[key];

		# If a measurement is done being collected, thresholds for each key
		# need to be checked so we're doing it here to avoid doubly iterating 
		# over each key.
		if ( Cluster::worker_count == done_with[uid] )
			{
			if ( check_thresholds(m, key, local_data[key], 1.0) )
				{
				threshold_crossed(m, key, local_data[key]);
				}
			}
		}
	
	# If the data has been collected from all peers, we are done and ready to finish.
	if ( Cluster::worker_count == done_with[uid] )
		{
		if ( m?$epoch_finished )
			m$epoch_finished(local_data);

		# Clean up
		delete measurement_results[uid];
		delete done_with[uid];
		# Not sure I need to reset the measurement on the manager.
		reset(m);
		}
	}

event remote_connection_handshake_done(p: event_peer) &priority=5
	{
	send_id(p, "Measurement::measurement_store");
	send_id(p, "Measurement::reducer_store");
	}
@endif
