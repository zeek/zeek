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
	## requirement that the manager requests a global view for the index
	## since it may opt not to if it requested a global view for the index
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

	# Event sent by the manager in a cluster to initiate the 
	# collection of metrics values for a filter.
	global cluster_filter_request: event(uid: string, id: string, filter_name: string);

	# Event sent by nodes that are collecting metrics after receiving
	# a request for the metric filter from the manager.
	global cluster_filter_response: event(uid: string, id: string, filter_name: string, data: MetricTable, done: bool);

	# This event is sent by the manager in a cluster to initiate the
	# collection of a single index value from a filter.  It's typically
	# used to get intermediate updates before the break interval triggers
	# to speed detection of a value crossing a threshold.
	global cluster_index_request: event(uid: string, id: string, filter_name: string, index: Index);

	# This event is sent by nodes in response to a 
	# :bro:id:`Measurement::cluster_index_request` event.
	global cluster_index_response: event(uid: string, id: string, filter_name: string, index: Index, val: ResultVal);

	# This is sent by workers to indicate that they crossed the percent of the 
	# current threshold by the percentage defined globally in 
	# :bro:id:`Measurement::cluster_request_global_view_percent`
	global cluster_index_intermediate_response: event(id: string, filter_name: string, index: Measurement::Index);

	# This event is scheduled internally on workers to send result chunks.
	global send_data: event(uid: string, id: string, filter_name: string, data: MetricTable);
}


# Add events to the cluster framework to make this work.
redef Cluster::manager2worker_events += /Measurement::cluster_(filter_request|index_request)/;
redef Cluster::worker2manager_events += /Measurement::cluster_(filter_response|index_response|index_intermediate_response)/;

@if ( Cluster::local_node_type() != Cluster::MANAGER )
# This variable is maintained to know what indexes they have recently sent as 
# intermediate updates so they don't overwhelm their manager. The count that is
# yielded is the number of times the percentage threshold has been crossed and
# an intermediate result has been received.
global recent_global_view_indexes: table[string, string, Index] of count &create_expire=1min &default=0;

# This is done on all non-manager node types in the event that a metric is 
# being collected somewhere other than a worker.
function data_added(filter: Filter, index: Index, val: ResultVal)
	{
	# If an intermediate update for this value was sent recently, don't send
	# it again.
	if ( [filter$id, filter$name, index] in recent_global_view_indexes )
		return;

	# If val is 5 and global view % is 0.1 (10%), pct_val will be 50.  If that
	# crosses the full threshold then it's a candidate to send as an 
	# intermediate update.
	if ( enable_intermediate_updates && 
	     check_thresholds(filter, index, val, cluster_request_global_view_percent) )
		{
		# kick off intermediate update
		event Measurement::cluster_index_intermediate_response(filter$id, filter$name, index);
		++recent_global_view_indexes[filter$id, filter$name, index];
		}
	}

event Measurement::send_data(uid: string, id: string, filter_name: string, data: MetricTable)
	{
	#print fmt("WORKER %s: sending data for uid %s...", Cluster::node, uid);
	
	local local_data: MetricTable;
	local num_added = 0;
	for ( index in data )
		{
		local_data[index] = data[index];
		delete data[index];
		
		# Only send cluster_send_in_groups_of at a time.  Queue another
		# event to send the next group.
		if ( cluster_send_in_groups_of == ++num_added )
			break;
		}
	
	local done = F;
	# If data is empty, this metric is done.
	if ( |data| == 0 )
		done = T;
	
	event Measurement::cluster_filter_response(uid, id, filter_name, local_data, done);
	if ( ! done )
		event Measurement::send_data(uid, id, filter_name, data);
	}

event Measurement::cluster_filter_request(uid: string, id: string, filter_name: string)
	{
	#print fmt("WORKER %s: received the cluster_filter_request event for %s.", Cluster::node, id);
	
	# Initiate sending all of the data for the requested filter.
	event Measurement::send_data(uid, id, filter_name, store[id, filter_name]);
	
	# Lookup the actual filter and reset it, the reference to the data
	# currently stored will be maintained internally by the send_data event.
	reset(filter_store[id, filter_name]);
	}
	
event Measurement::cluster_index_request(uid: string, id: string, filter_name: string, index: Index)
	{
	if ( [id, filter_name] in store && index in store[id, filter_name] )
		{
		#print fmt("WORKER %s: received the cluster_index_request event for %s=%s.", Cluster::node, index2str(index), data);
		event Measurement::cluster_index_response(uid, id, filter_name, index, store[id, filter_name][index]);
		}
	else
		{
		# We need to send an empty response if we don't have the data so that the manager
		# can know that it heard back from all of the workers.
		event Measurement::cluster_index_response(uid, id, filter_name, index, [$begin=network_time(), $end=network_time()]);
		}
	}

@endif


@if ( Cluster::local_node_type() == Cluster::MANAGER )

# This variable is maintained by manager nodes as they collect and aggregate 
# results.
global filter_results: table[string, string, string] of MetricTable &read_expire=1min;

# This is maintained by managers so they can know what data they requested and
# when they requested it.
global requested_results: table[string] of time = table() &create_expire=5mins;

# This variable is maintained by manager nodes to track how many "dones" they
# collected per collection unique id.  Once the number of results for a uid 
# matches the number of peer nodes that results should be coming from, the 
# result is written out and deleted from here.
# TODO: add an &expire_func in case not all results are received.
global done_with: table[string] of count &read_expire=1min &default=0;

# This variable is maintained by managers to track intermediate responses as 
# they are getting a global view for a certain index.
global index_requests: table[string, string, string, Index] of ResultVal &read_expire=1min;

# This variable is maintained by managers to prevent overwhelming communication due
# to too many intermediate updates.  Each metric filter is tracked separately so that 
# one metric won't overwhelm and degrade other quieter metrics.
global outstanding_global_views: table[string, string] of count &default=0;

# Managers handle logging.
event Measurement::finish_period(filter: Filter)
	{
	#print fmt("%.6f MANAGER: breaking %s filter for %s metric", network_time(), filter$name, filter$id);
	local uid = unique_id("");
	
	# Set some tracking variables.
	requested_results[uid] = network_time();
	if ( [uid, filter$id, filter$name] in filter_results )
		delete filter_results[uid, filter$id, filter$name];
	filter_results[uid, filter$id, filter$name] = table();
	
	# Request data from peers.
	event Measurement::cluster_filter_request(uid, filter$id, filter$name);
	# Schedule the next finish_period event.
	schedule filter$every { Measurement::finish_period(filter) };
	}

# This is unlikely to be called often, but it's here in case there are metrics
# being collected by managers.
function data_added(filter: Filter, index: Index, val: ResultVal)
	{
	if ( check_thresholds(filter, index, val, 1.0) )
		threshold_crossed(filter, index, val);
	}
	
event Measurement::cluster_index_response(uid: string, id: string, filter_name: string, index: Index, val: ResultVal)
	{
	#print fmt("%0.6f MANAGER: receiving index data from %s - %s=%s", network_time(), get_event_peer()$descr, index2str(index), val);

	# We only want to try and do a value merge if there are actually measured datapoints
	# in the ResultVal.
	if ( val$num > 0 && [uid, id, filter_name, index] in index_requests )
		index_requests[uid, id, filter_name, index] = merge_result_vals(index_requests[uid, id, filter_name, index], val);
	else
		index_requests[uid, id, filter_name, index] = val;

	# Mark that this worker is done.
	++done_with[uid];

	#print fmt("worker_count:%d :: done_with:%d", Cluster::worker_count, done_with[uid]);
	if ( Cluster::worker_count == done_with[uid] )
		{
		local ir = index_requests[uid, id, filter_name, index];
		if ( check_thresholds(filter_store[id, filter_name], index, ir, 1.0) )
			{
			threshold_crossed(filter_store[id, filter_name], index, ir);
			}
		delete done_with[uid];
		delete index_requests[uid, id, filter_name, index];
		# Check that there is an outstanding view before subtracting.
		if ( outstanding_global_views[id, filter_name] > 0 )
			--outstanding_global_views[id, filter_name];
		}
	}

# Managers handle intermediate updates here.
event Measurement::cluster_index_intermediate_response(id: string, filter_name: string, index: Index)
	{
	#print fmt("MANAGER: receiving intermediate index data from %s", get_event_peer()$descr);
	#print fmt("MANAGER: requesting index data for %s", index2str(index));

	if ( [id, filter_name] in outstanding_global_views &&
	     |outstanding_global_views[id, filter_name]| > max_outstanding_global_views )
		{
		# Don't do this intermediate update.  Perhaps at some point in the future 
		# we will queue and randomly select from these ignored intermediate
		# update requests.
		return;
		}

	++outstanding_global_views[id, filter_name];

	local uid = unique_id("");
	event Measurement::cluster_index_request(uid, id, filter_name, index);
	}

event Measurement::cluster_filter_response(uid: string, id: string, filter_name: string, data: MetricTable, done: bool)
	{
	#print fmt("MANAGER: receiving results from %s", get_event_peer()$descr);
	
	# Mark another worker as being "done" for this uid.
	if ( done )
		++done_with[uid];

	local local_data = filter_results[uid, id, filter_name];
	local filter = filter_store[id, filter_name];

	for ( index in data )
		{
		if ( index in local_data )
			local_data[index] = merge_result_vals(local_data[index], data[index]);
		else
			local_data[index] = data[index];

		# If a filter is done being collected, thresholds for each index
		# need to be checked so we're doing it here to avoid doubly iterating 
		# over each index.
		if ( Cluster::worker_count == done_with[uid] )
			{
			if ( check_thresholds(filter, index, local_data[index], 1.0) )
				{
				threshold_crossed(filter, index, local_data[index]);
				}
			}
		}
	
	# If the data has been collected from all peers, we are done and ready to finish.
	if ( Cluster::worker_count == done_with[uid] )
		{
		local ts = network_time();
		# Log the time this was initially requested if it's available.
		if ( uid in requested_results )
			{
			ts = requested_results[uid];
			delete requested_results[uid];
			}
		
		if ( filter?$period_finished )
			filter$period_finished(ts, filter$id, filter$name, local_data);

		# Clean up
		delete filter_results[uid, id, filter_name];
		delete done_with[uid];
		# Not sure I need to reset the filter on the manager.
		reset(filter);
		}
	}

@endif
