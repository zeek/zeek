##! This implements transparent cluster support for the SumStats framework.
##! Do not load this file directly.  It's only meant to be loaded automatically
##! and will be if the cluster framework has been enabled.
##! The goal of this script is to make sumstats calculation completely and
##! transparently automated when running on a cluster.

@load base/frameworks/cluster
@load ./main

module SumStats;

export {
	## The percent of the full threshold value that needs to be met on a
	## single worker for that worker to send the value to its manager in
	## order for it to request a global view for that value.  There is no
	## requirement that the manager requests a global view for the key since
	## it may opt not to if it requested a global view for the key recently.
	const cluster_request_global_view_percent = 0.2 &redef;

	## This is to deal with intermediate update overload.  A manager will
	## only allow this many intermediate update requests to the workers to
	## be inflight at any given time.  Requested intermediate updates are
	## currently thrown out and not performed.  In practice this should
	## hopefully have a minimal effect.
	const max_outstanding_global_views = 10 &redef;

	## Event sent by the manager in a cluster to initiate the collection of
	## values for a sumstat.
	global cluster_ss_request: event(uid: string, ss_name: string, cleanup: bool);

	# Event sent by nodes that are collecting sumstats after receiving a
	# request for the sumstat from the manager.
	#global cluster_ss_response: event(uid: string, ss_name: string, data: ResultTable, done: bool, cleanup: bool);

	## This event is sent by the manager in a cluster to initiate the
	## collection of a single key value from a sumstat.  It's typically used
	## to get intermediate updates before the break interval triggers to
	## speed detection of a value crossing a threshold.
	global cluster_get_result: event(uid: string, ss_name: string, key: Key, cleanup: bool);

	## This event is sent by nodes in response to a
	## :bro:id:`SumStats::cluster_get_result` event.
	global cluster_send_result: event(uid: string, ss_name: string, key: Key, result: Result, cleanup: bool);

	## This is sent by workers to indicate that they crossed the percent
	## of the current threshold by the percentage defined globally in
	## :bro:id:`SumStats::cluster_request_global_view_percent`.
	global cluster_key_intermediate_response: event(ss_name: string, key: SumStats::Key);

	## This event is scheduled internally on workers to send result chunks.
	global send_data: event(uid: string, ss_name: string, data: ResultTable, cleanup: bool);

	global get_a_key: event(uid: string, ss_name: string, cleanup: bool &default=F);

	global send_a_key: event(uid: string, ss_name: string, key: Key);
	global send_no_key: event(uid: string, ss_name: string);

	## This event is generated when a threshold is crossed.
	global cluster_threshold_crossed: event(ss_name: string, key: SumStats::Key, thold_index: count);
}

# Add events to the cluster framework to make this work.
redef Cluster::manager2worker_events += /SumStats::cluster_(ss_request|get_result|threshold_crossed)/;
redef Cluster::manager2worker_events += /SumStats::(get_a_key)/;
redef Cluster::worker2manager_events += /SumStats::cluster_(send_result|key_intermediate_response)/;
redef Cluster::worker2manager_events += /SumStats::(send_a_key|send_no_key)/;

@if ( Cluster::local_node_type() != Cluster::MANAGER )
# This variable is maintained to know what keys have recently sent as
# intermediate updates so they don't overwhelm their manager. The count that is
# yielded is the number of times the percentage threshold has been crossed and
# an intermediate result has been received.
global recent_global_view_keys: table[string, Key] of count &create_expire=1min &default=0;

# Result tables indexed on a uid that are currently being sent to the
# manager.
global sending_results: table[string] of ResultTable = table() &read_expire=1min;

# This is done on all non-manager node types in the event that a sumstat is
# being collected somewhere other than a worker.
function data_added(ss: SumStat, key: Key, result: Result)
	{
	# If an intermediate update for this value was sent recently, don't send
	# it again.
	if ( [ss$name, key] in recent_global_view_keys )
		return;

	# If val is 5 and global view % is 0.1 (10%), pct_val will be 50.  If that
	# crosses the full threshold then it's a candidate to send as an
	# intermediate update.
	if ( check_thresholds(ss, key, result, cluster_request_global_view_percent) )
		{
		# kick off intermediate update
		event SumStats::cluster_key_intermediate_response(ss$name, key);
		++recent_global_view_keys[ss$name, key];
		}
	}

event SumStats::get_a_key(uid: string, ss_name: string, cleanup: bool)
	{
	if ( uid in sending_results )
		{
		if ( |sending_results[uid]| == 0 )
			{
			event SumStats::send_no_key(uid, ss_name);
			}
		else
			{
			for ( key in sending_results[uid] )
				{
				event SumStats::send_a_key(uid, ss_name, key);
				# break to only send one.
				break;
				}
			}
		}
	else if ( !cleanup && ss_name in result_store && |result_store[ss_name]| > 0 )
		{
		if ( |result_store[ss_name]| == 0 )
			{
			event SumStats::send_no_key(uid, ss_name);
			}
		else
			{
			for ( key in result_store[ss_name] )
				{
				event SumStats::send_a_key(uid, ss_name, key);
				# break to only send one.
				break;
				}
			}
		}
	else
		{
		event SumStats::send_no_key(uid, ss_name);
		}
	}

event SumStats::cluster_ss_request(uid: string, ss_name: string, cleanup: bool)
	{
	#print fmt("WORKER %s: received the cluster_ss_request event for %s.", Cluster::node, id);

	# Create a back store for the result
	sending_results[uid] = (ss_name in result_store) ? result_store[ss_name] : table();

	# Lookup the actual sumstats and reset it, the reference to the data
	# currently stored will be maintained internally from the 
	# sending_results table.
	if ( cleanup && ss_name in stats_store )
		reset(stats_store[ss_name]);
	}

event SumStats::cluster_get_result(uid: string, ss_name: string, key: Key, cleanup: bool)
	{
	#print fmt("WORKER %s: received the cluster_get_result event for %s=%s.", Cluster::node, key2str(key), data);

	if ( cleanup ) # data will implicitly be in sending_results (i know this isn't great)
		{
		if ( uid in sending_results && key in sending_results[uid] )
			{
			# Note: copy is needed to compensate serialization caching issue. This should be
			# changed to something else later. 
			event SumStats::cluster_send_result(uid, ss_name, key, copy(sending_results[uid][key]), cleanup);
			delete sending_results[uid][key];
			}
		else
			{
			# We need to send an empty response if we don't have the data so that the manager
			# can know that it heard back from all of the workers.
			event SumStats::cluster_send_result(uid, ss_name, key, table(), cleanup);
			}
		}
	else 
		{
		if ( ss_name in result_store && key in result_store[ss_name] )
			{
			# Note: copy is needed to compensate serialization caching issue. This should be
			# changed to something else later. 
			event SumStats::cluster_send_result(uid, ss_name, key, copy(result_store[ss_name][key]), cleanup);
			}
		else
			{
			# We need to send an empty response if we don't have the data so that the manager
			# can know that it heard back from all of the workers.
			event SumStats::cluster_send_result(uid, ss_name, key, table(), cleanup);
			}
		}
	}

event SumStats::cluster_threshold_crossed(ss_name: string, key: SumStats::Key, thold_index: count)
	{
	if ( ss_name !in threshold_tracker )
		threshold_tracker[ss_name] = table();

	threshold_tracker[ss_name][key] = thold_index;
	}

@endif


@if ( Cluster::local_node_type() == Cluster::MANAGER )

# This variable is maintained by manager nodes as they collect and aggregate
# results.
# Index on a uid.
global stats_keys: table[string] of set[Key] &read_expire=1min 
	&expire_func=function(s: table[string] of set[Key], idx: string): interval
		{
		Reporter::warning(fmt("SumStat key request for the %s SumStat uid took longer than 1 minute and was automatically cancelled.", idx));
		return 0secs;
		};

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

# Store uids for dynamic requests here to avoid cleanup on the uid.
# (This needs to be done differently!)
global dynamic_requests: set[string] &read_expire=1min;

# This variable is maintained by managers to prevent overwhelming communication due
# to too many intermediate updates.  Each sumstat is tracked separately so that
# one won't overwhelm and degrade other quieter sumstats.
# Indexed on a sumstat id.
global outstanding_global_views: table[string] of count &read_expire=1min &default=0;

const zero_time = double_to_time(0.0);
# Managers handle logging.
event SumStats::finish_epoch(ss: SumStat)
	{
	if ( network_time() > zero_time )
		{
		#print fmt("%.6f MANAGER: breaking %s sumstat", network_time(), ss$name);
		local uid = unique_id("");

		if ( uid in stats_keys )
			delete stats_keys[uid];
		stats_keys[uid] = set();

		# Request data from peers.
		event SumStats::cluster_ss_request(uid, ss$name, T);

		done_with[uid] = 0;

		#print fmt("get_key by uid: %s", uid);
		event SumStats::get_a_key(uid, ss$name, T);
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
		event SumStats::cluster_threshold_crossed(ss$name, key, threshold_tracker[ss$name][key]);
		}
	}

function handle_end_of_result_collection(uid: string, ss_name: string, key: Key, cleanup: bool)
	{
	if ( uid !in key_requests )
		{
		Reporter::warning(fmt("Tried to handle end of result collection with missing uid in key_request sumstat:%s, key:%s.", ss_name, key));
		return;
		}

	#print fmt("worker_count:%d :: done_with:%d", Cluster::worker_count, done_with[uid]);
	local ss = stats_store[ss_name];
	local ir = key_requests[uid];
	if ( check_thresholds(ss, key, ir, 1.0) )
		{
		threshold_crossed(ss, key, ir);
		event SumStats::cluster_threshold_crossed(ss_name, key, threshold_tracker[ss_name][key]);
		}

	if ( cleanup )
		{
		# This is done here because "cleanup" implicitly means
		# it's the end of an epoch.
		if ( ss?$epoch_result && |ir| > 0 )
			{
			local now = network_time();
			ss$epoch_result(now, key, ir);
			}

		# Check that there is an outstanding view before subtracting.
		# Global views only apply to non-dynamic requests. Dynamic
		# requests must be serviced.
		if ( outstanding_global_views[ss_name] > 0 )
			--outstanding_global_views[ss_name];
		}

	delete key_requests[uid];
	delete done_with[uid];
	}

function request_all_current_keys(uid: string, ss_name: string, cleanup: bool)
	{
	#print "request_all_current_keys";
	if ( uid in stats_keys && |stats_keys[uid]| > 0 )
		{
		#print fmt("    -- %d remaining keys here", |stats_keys[uid]|);
		for ( key in stats_keys[uid] )
			{
			done_with[uid] = 0;
			event SumStats::cluster_get_result(uid, ss_name, key, cleanup);
			delete stats_keys[uid][key];
			break; # only a single key
			}
		}
	else
		{
		# Get more keys!  And this breaks us out of the evented loop.
		done_with[uid] = 0;
		#print fmt("get_key by uid: %s", uid);
		event SumStats::get_a_key(uid, ss_name, cleanup);
		}
	}

event SumStats::send_no_key(uid: string, ss_name: string)
	{
	#print "send_no_key";

	if ( uid !in done_with )
		done_with[uid] = 0;

	++done_with[uid];
	if ( Cluster::worker_count == done_with[uid] )
		{
		delete done_with[uid];

		if ( uid in stats_keys && |stats_keys[uid]| > 0 )
			{
			#print "we need more keys!";
			# Now that we have a key from each worker, lets
			# grab all of the results.
			request_all_current_keys(uid, ss_name, T);
			}
		else
			{
			#print "we're out of keys!";
			local ss = stats_store[ss_name];
			if ( ss?$epoch_finished )
				ss$epoch_finished(network_time());

			delete stats_keys[uid];
			reset(ss);
			}
		}
	}

event SumStats::send_a_key(uid: string, ss_name: string, key: Key)
	{
	#print fmt("send_a_key %s", key);
	if ( uid !in stats_keys )
		{
		Reporter::warning(fmt("Manager received a uid for an unknown request.  SumStat: %s, Key: %s", ss_name, key));
		return;
		}

	if ( key !in stats_keys[uid] )
		add stats_keys[uid][key];

	++done_with[uid];
	if ( Cluster::worker_count == done_with[uid] )
		{
		delete done_with[uid];

		if ( |stats_keys[uid]| > 0 )
			{
			#print "we need more keys!";
			# Now that we have a key from each worker, lets
			# grab all of the results.
			request_all_current_keys(uid, ss_name, T);
			}
		else
			{
			#print "we're out of keys!";
			local ss = stats_store[ss_name];
			if ( ss?$epoch_finished )
				ss$epoch_finished(network_time());

			reset(ss);
			}
		}
	}

event SumStats::cluster_send_result(uid: string, ss_name: string, key: Key, result: Result, cleanup: bool)
	{
	#print "cluster_send_result";
	#print fmt("%0.6f MANAGER: receiving key data from %s - %s=%s", network_time(), get_event_peer()$descr, key2str(key), result);

	# We only want to try and do a value merge if there are actually measured datapoints
	# in the Result.
	if ( uid !in key_requests || |key_requests[uid]| == 0 )
		key_requests[uid] = result;
	else
		key_requests[uid] = compose_results(key_requests[uid], result);

	# Mark that a worker is done.
	if ( uid !in done_with )
		done_with[uid] = 0;
	
	#print fmt("MANAGER: got a result for %s %s from %s", uid, key, get_event_peer()$descr);
	++done_with[uid];

	if ( uid !in dynamic_requests &&
	     uid in done_with && Cluster::worker_count == done_with[uid] )
		{
		handle_end_of_result_collection(uid, ss_name, key, cleanup);

		if ( cleanup )
			request_all_current_keys(uid, ss_name, cleanup);
		}
	}

# Managers handle intermediate updates here.
event SumStats::cluster_key_intermediate_response(ss_name: string, key: Key)
	{
	#print fmt("MANAGER: receiving intermediate key data from %s", get_event_peer()$descr);
	#print fmt("MANAGER: requesting key data for %s", key);

	if ( ss_name in outstanding_global_views &&
	     |outstanding_global_views[ss_name]| > max_outstanding_global_views )
		{
		# Don't do this intermediate update.  Perhaps at some point in the future
		# we will queue and randomly select from these ignored intermediate
		# update requests.
		return;
		}

	++outstanding_global_views[ss_name];

	local uid = unique_id("");
	done_with[uid] = 0;
	#print fmt("requesting results for: %s", uid);
	event SumStats::cluster_get_result(uid, ss_name, key, F);
	}

function request_key(ss_name: string, key: Key): Result
	{
	local uid = unique_id("");
	done_with[uid] = 0;
	key_requests[uid] = table();
	add dynamic_requests[uid];

	event SumStats::cluster_get_result(uid, ss_name, key, F);
	return when ( uid in done_with && Cluster::worker_count == done_with[uid] )
		{
		#print "done with request_key";
		local result = key_requests[uid];
		# Clean up
		delete key_requests[uid];
		delete done_with[uid];
		delete dynamic_requests[uid];

		return result;
		}
	timeout 1.1min
		{
		Reporter::warning(fmt("Dynamic SumStat key request for %s in SumStat %s took longer than 1 minute and was automatically cancelled.", key, ss_name));
		return Result();
		}
	}

@endif
