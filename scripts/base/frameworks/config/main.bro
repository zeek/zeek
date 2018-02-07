##! The configuration framework provides a way to change Bro options
##! (as specified by the option keyword) at runtime. It also logs runtime changes
##! to options to config.log.

module Config;

export {
	## The config logging stream identifier.
	redef enum Log::ID += { LOG };

	## Represents the data in config.log.
	type Info: record {
		## Timestamp at which the configuration change occured.
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

	## Event that can be handled to access the :bro:type:`Config::Info`
	## record as it is sent on to the logging framework.
	global log_config: event(rec: Info);
}

function format_value(value: any) : string
	{
	local tn = type_name(value);
	local part: string_vec = vector();
	if ( /^set/ in tn )
		{
		local it: set[bool] = value;
		for ( sv in it )
			part[|part|] = cat(sv);
		return join_string_vec(part, ",");
		}
	else if ( /^vector/ in tn )
		{
		local vit: vector of any = value;
		for ( i in vit )
			part[|part|] = cat(vit[i]);
		return join_string_vec(part, ",");
		}
	else if ( tn == "string" )
		return value;

	return cat(value);
	}

function config_option_changed(ID: string, new_value: any, location: string): any
	{
	local log = Info($ts=network_time(), $id=ID, $old_value=format_value(lookup_ID(ID)), $new_value=format_value(new_value));
	if ( location != "" )
		log$location = location;
	Log::write(LOG, log);
	return new_value;
	}

event bro_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_config, $path="config"]);

	# Iterate over all existing options and add ourselves as change handlers with
	# a low priority so that we can log the changes.
	local gids = global_ids();
	for ( i in gids )
		{
		if ( ! gids[i]$option_value )
			next;

		Option::set_change_handler(i, config_option_changed, -100);
		}
	}
