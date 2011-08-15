##! This implements transparent cluster support for the metrics framework.
##! Do not load this file directly.  It's only meant to be loaded automatically
##! and will be depending on if the cluster framework has been enabled.
##! The goal of this script is to make metric calculation completely and
##! transparently automated when running on a cluster.

@load base/frameworks/cluster
@load ./main

module Metrics;

export {
	## This event is sent by the manager in a cluster to initiate the 3
	## collection of metrics values 
	global cluster_collect: event(uid: string, id: ID, filter_name: string);
	
	## This event is sent by nodes that are collecting metrics after receiving
	## a request for the metric filter from the manager.
	global cluster_results: event(uid: string, id: ID, filter_name: string, data: MetricTable, done: bool);
	
	## This event is used internally by workers to send result chunks.
	global send_data: event(uid: string, id: ID, filter_name: string, data: MetricTable);
	
	## This value allows a user to decide how large of result groups the 
	## workers should transmit values.
	const cluster_send_in_groups_of = 50 &redef;
}

# This is maintained by managers so they can know what data they requested and
# when they requested it.
global requested_results: table[string] of time = table() &create_expire=5mins;

# TODO: Both of the next variables make the assumption that a value never 
#       takes longer than 5 minutes to transmit from workers to manager.  This needs to 
#       be tunable or self-tuning.  These should also be restructured to be
#       maintained within a single variable.
# This variable is maintained by manager nodes as they collect and aggregate 
# results.
global collecting_results: table[string, ID, string] of MetricTable &create_expire=5mins;

# This variable is maintained by manager nodes to track how many "dones" they
# collected per collection unique id.  Once the number of results for a uid 
# matches the number of peer nodes that results should be coming from, the 
# result is written out and deleted from here.
# TODO: add an &expire_func in case not all results are received.
global done_with: table[string] of count &create_expire=5mins &default=0;

# Add events to the cluster framework to make this work.
redef Cluster::manager_events += /Metrics::cluster_collect/;
redef Cluster::worker_events += /Metrics::cluster_results/;

# The metrics collection process can only be done by a manager.
@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Metrics::log_it(filter: Filter)
	{
	local uid = unique_id("");
	
	# Set some tracking variables.
	requested_results[uid] = network_time();
	collecting_results[uid, filter$id, filter$name] = table();
	
	# Request data from peers.
	event Metrics::cluster_collect(uid, filter$id, filter$name);
	# Schedule the log_it event for the next break period.
	schedule filter$break_interval { Metrics::log_it(filter) };
	}
@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )

event Metrics::send_data(uid: string, id: ID, filter_name: string, data: MetricTable)
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
	
	event Metrics::cluster_results(uid, id, filter_name, local_data, done);
	if ( ! done )
		event Metrics::send_data(uid, id, filter_name, data);
	}

event Metrics::cluster_collect(uid: string, id: ID, filter_name: string)
	{
	#print fmt("WORKER %s: received the cluster_collect event.", Cluster::node);
	
	event Metrics::send_data(uid, id, filter_name, store[id, filter_name]);
		
	# Lookup the actual filter and reset it, the reference to the data
	# currently stored will be maintained interally by the send_data event.
	reset(filter_store[id, filter_name]);
	}
@endif


@if ( Cluster::local_node_type() == Cluster::MANAGER )

event Metrics::cluster_results(uid: string, id: ID, filter_name: string, data: MetricTable, done: bool)
	{
	#print fmt("MANAGER: receiving results from %s", get_event_peer()$descr);
	
	local local_data = collecting_results[uid, id, filter_name];
	for ( index in data )
		{
		if ( index !in local_data )
			local_data[index] = 0;
		local_data[index] += data[index];
		}
	
	# Mark another worker as being "done" for this uid.
	if ( done )
		++done_with[uid];
	
	# If the data has been collected from all peers, we are done and ready to log.
	if ( Cluster::worker_count == done_with[uid] )
		{
		local ts = network_time();
		# Log the time this was initially requested if it's available.
		if ( uid in requested_results )
			ts = requested_results[uid];
			
		write_log(ts, filter_store[id, filter_name], local_data);
		if ( [uid, id, filter_name] in collecting_results )
			delete collecting_results[uid, id, filter_name];
		if ( uid in done_with )
			delete done_with[uid];
		if ( uid in requested_results )
			delete requested_results[uid];
		}
	}

@endif
