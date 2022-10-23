##! The configuration framework provides a way to change Zeek options
##! (as specified by the "option" keyword) at runtime. It also logs runtime
##! changes to options to config.log.

@load base/frameworks/cluster

module Config;

export {
	## The config logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Represents the data in config.log.
	type Info: record {
		## Timestamp at which the configuration change occurred.
		ts: time &log;
		## ID of the value that was changed.
		id: string &log;
		## Value before the change.
		old_value: string &log;
		## Value after the change.
		new_value: string &log;
		## Optional location that triggered the change.
		location: string &optional &log;
	};

	## Event that can be handled to access the :zeek:type:`Config::Info`
	## record as it is sent on to the logging framework.
	global log_config: event(rec: Info);

	## This function is the config framework layer around the lower-level
	## :zeek:see:`Option::set` call. Config::set_value will set the configuration
	## value for all nodes in the cluster, no matter where it was called. Note
	## that :zeek:see:`Option::set` does not distribute configuration changes
	## to other nodes.
	##
	## ID: The ID of the option to update.
	##
	## val: The new value of the option.
	##
	## location: Optional parameter detailing where this change originated from.
	##
	## Returns: true on success, false when an error occurs.
	global set_value: function(ID: string, val: any, location: string &default = ""): bool;
}

@if ( Cluster::is_enabled() )
type OptionCacheValue: record {
	val: any;
	location: string;
};

global option_cache: table[string] of OptionCacheValue;

global Config::cluster_set_option: event(ID: string, val: any, location: string);

function broadcast_option(ID: string, val: any, location: string) &is_used
	{
	# There's not currently a common topic to broadcast to as then enabling
	# implicit Broker forwarding would cause a routing loop.
	Broker::publish(Cluster::worker_topic, Config::cluster_set_option,
	                ID, val, location);
	Broker::publish(Cluster::proxy_topic, Config::cluster_set_option,
	                ID, val, location);
	Broker::publish(Cluster::logger_topic, Config::cluster_set_option,
	                ID, val, location);
	}

event Config::cluster_set_option(ID: string, val: any, location: string)
	{
@if ( Cluster::local_node_type() == Cluster::MANAGER )
	option_cache[ID] = OptionCacheValue($val=val, $location=location);
	broadcast_option(ID, val, location);
@endif

	Option::set(ID, val, location);
	}

function set_value(ID: string, val: any, location: string &default = ""): bool
	{
	# Always copy the value to break references -- if caller mutates their
	# value afterwards, we still guarantee the option has not changed.  If
	# one wants it to change, they need to explicitly call Option::set_value
	# or Option::set with the intended value at the time of the call.
	val = copy(val);

	# First try setting it locally - abort if not possible.
	if ( ! Option::set(ID, val, location) )
		return F;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
	option_cache[ID] = OptionCacheValue($val=val, $location=location);
	broadcast_option(ID, val, location);
@else
	Broker::publish(Cluster::manager_topic, Config::cluster_set_option,
	                ID, val, location);
@endif

	return T;
	}
@else # Standalone implementation
function set_value(ID: string, val: any, location: string &default = ""): bool
	{
	return Option::set(ID, val, location);
	}
@endif # Cluster::is_enabled

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
# Handling of new worker nodes.
event Cluster::node_up(name: string, id: string) &priority=-10
	{
	# When a node connects, send it all current Option values.
	if ( name in Cluster::nodes )
		for ( ID in option_cache )
			Broker::publish(Cluster::node_topic(name), Config::cluster_set_option, ID, option_cache[ID]$val, option_cache[ID]$location);
	}
@endif


function format_value(value: any) : string
	{
	local tn = type_name(value);
	local part: string_vec = vector();

	if ( /^set/ in tn && strstr(tn, ",") == 0 )
		{
		local vec = Option::any_set_to_any_vec(value);
		for ( sv in vec )
			part += cat(vec[sv]);
		return join_string_vec(part, ",");
		}
	else if ( /^vector/ in tn )
		{
		local vit: vector of any = value;
		for ( i in vit )
			part += cat(vit[i]);
		return join_string_vec(part, ",");
		}
	else if ( tn == "string" )
		return value;

	return cat(value);
	}

function config_option_changed(ID: string, new_value: any, location: string): any &is_used
	{
	local log = Info($ts=network_time(), $id=ID, $old_value=format_value(lookup_ID(ID)), $new_value=format_value(new_value));
	if ( location != "" )
		log$location = location;
	Log::write(LOG, log);
	return new_value;
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_config, $path="config", $policy=log_policy]);

	# Limit logging to the manager - everyone else just feeds off it.
@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
	# Iterate over all existing options and add ourselves as change handlers
	# with a low priority so that we can log the changes.
	for ( opt in global_options() )
		Option::set_change_handler(opt, config_option_changed, -100);
@endif
	}
