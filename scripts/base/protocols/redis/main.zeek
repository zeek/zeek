@load base/protocols/conn/removal-hooks
@load base/frameworks/signatures

module Redis;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register Redis for.
	const ports = { 6379/tcp } &redef;

	type SetCommand: record {
		key: string &log;
		value: string &log;
		nx: bool;
		xx: bool;
		get: bool;
		ex: count &optional;
		px: count &optional;
		exat: count &optional;
		pxat: count &optional;
		keep_ttl: bool;
	};

	type GetCommand: record {
		key: string &log;
	};

	type AuthCommand: record {
		username: string &optional;
		password: string;
	};

	type Command: record {
		## The raw command, exactly as parsed
		raw: vector of string;
		## The first element of the command. Some commands are two strings, meaning this
		## is inaccurate for those cases.
		command: string &log;
		## The key, if this command is known to have a key
		key: string &log &optional;
		## The value, if this command is known to have a value
		value: string &log &optional;
		## The command in an enum if it was known
		known: Redis::KnownCommand &optional;
	};

	type ServerData: record {
		## Was this an error?
		err: bool &log;
		## The string response, if it was a simple string or error
		data: string &log &optional;
	};

	## Record type containing the column fields of the Redis log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The Redis command
		cmd: Command &log &optional;
		## The response for the command
		response: ServerData &log &optional;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into Redis logging.
	global log_resp: event(rec: Info);

	global finalize_redis: Conn::RemovalHook;

	type State: record {
		## Pending requests.
		pending: table[count] of Info;
		## Current request in the pending queue.
		current_request: count &default=0;
		## Current response in the pending queue.
		current_response: count &default=0;
		## Ranges where we do not expect a response
		## Each range is one or two elements, one meaning it's unbounded, two meaning
		## it begins at one and ends at the second.
		no_response_ranges: vector of vector of count;
		## We store if this analyzer had a violation to avoid logging if so.
		## This should not be super necessary, but worth a shot.
		violation: bool &default=F;
	};

	# Redis specifically mentions 10k commands as a good pipelining threshold, so
	# we'll piggyback on that.
	option max_pending_requests = 10000;
}

redef record connection += {
	redis: Info &optional;
	redis_state: State &optional;
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(Redis::LOG, [ $columns=Info, $ev=log_resp, $path="redis",
	    $policy=log_policy ]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_REDIS, ports);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag,
    info: AnalyzerViolationInfo)
	{
	if ( atype == Analyzer::ANALYZER_SPICY_REDIS )
		{
		if ( info?$c )
			{
			if ( info$c?$redis_state )
				{
				info$c$redis_state$violation = T;
				}
			}
		}
	}

function new_redis_session(c: connection): Info
	{
	return Info($ts=network_time(), $uid=c$uid, $id=c$id);
	}

function make_new_state(c: connection)
	{
	local s: State;
	c$redis_state = s;
	Conn::register_removal_hook(c, finalize_redis);
	}

function set_state(c: connection, is_orig: bool)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	local current: count;
	if ( is_orig )
		current = c$redis_state$current_request;
	else
		current = c$redis_state$current_response;

	if ( current !in c$redis_state$pending )
		c$redis_state$pending[current] = new_redis_session(c);

	c$redis = c$redis_state$pending[current];
	}

# Returns true if the last interval exists and is closed
function is_last_interval_closed(c: connection): bool
	{
	return |c$redis_state$no_response_ranges| == 0
	    || |c$redis_state$no_response_ranges[|c$redis_state$no_response_ranges| - 1]| != 1;
	}

event Redis::command(c: connection, is_orig: bool, command: Command)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	if ( max_pending_requests > 0
	    && |c$redis_state$pending| > max_pending_requests )
		{
		Reporter::conn_weird("Redis_excessive_pipelining", c);
		# Delete the current state and restart later. We'll be in a weird state, but
		# really we want to abort. I don't quite get how to register this as a
		# violation. :)
		delete c$redis_state;
		return;
		}

	++c$redis_state$current_request;
	if ( command?$known && command$known == KnownCommand_CLIENT )
		{
		# All 3 CLIENT commands we care about have 3 elements
		if ( |command$raw| == 3 )
			{
			if ( to_lower(command$raw[2]) == "on" )
				{
				# If the last range is open, close it here. Otherwise, noop
				if ( |c$redis_state$no_response_ranges| > 0 )
					{
					local range = c$redis_state$no_response_ranges[|c$redis_state$no_response_ranges|
					    - 1];
					if ( |range| == 1 )
						{
						range += c$redis_state$current_request;
						}
					}
				}
			if ( to_lower(command$raw[2]) == "off" )
				{
				# Only add a new interval if the last one is closed
				if ( is_last_interval_closed(c) )
					{
					c$redis_state$no_response_ranges += vector(c$redis_state$current_request);
					}
				}
			if ( to_lower(command$raw[2]) == "skip" )
				{
				if ( is_last_interval_closed(c) )
					# It skips this one and the next one
					c$redis_state$no_response_ranges += vector(c$redis_state$current_request,
					    c$redis_state$current_request + 2);
				}
			}
		}
	set_state(c, T);

	c$redis$cmd = command;
	}

## Gets the next response number based on a connection. This is necessary since
## some responses may have been skipped.
function response_num(c: connection): count
	{
	local resp_num = c$redis_state$current_response + 1;
	for ( i in c$redis_state$no_response_ranges )
		{
		local range = c$redis_state$no_response_ranges[i];
		assert | range |  >= 1;
		if ( |range| == 1 && resp_num > range[0] )
			{ } # TODO: This is necessary if not using pipelining
		if ( |range| == 2 && resp_num >= range[0] && resp_num < range[1] )
			return range[1];
		}

	# Default: no disable/enable shenanigans
	return resp_num;
	}

event Redis::server_data(c: connection, is_orig: bool, data: ServerData)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	local previous_response_num = c$redis_state$current_response;
	c$redis_state$current_response = response_num(c);
	set_state(c, F);

	c$redis$response = data;
	# Log each of the pending responses to this point - we will not go
	# back.
	while ( previous_response_num < c$redis_state$current_response )
		{
		if ( previous_response_num == 0 )
			{
			++previous_response_num;
			next;
			}

		if ( previous_response_num in c$redis_state$pending &&
		    c$redis_state$pending[previous_response_num]?$cmd )
			{
			Log::write(Redis::LOG, c$redis_state$pending[previous_response_num]);
			delete c$redis_state$pending[previous_response_num];
			}
		previous_response_num += 1;
		}
	# Log this one if we have the request and response
	if ( c$redis?$cmd )
		{
		Log::write(Redis::LOG, c$redis);
		delete c$redis_state$pending[c$redis_state$current_response];
		}
	}

hook finalize_redis(c: connection)
	{
	if ( c$redis_state$violation )
		{
		# If there's a violation, make sure everything gets deleted
		delete c$redis_state;
		}
	# Flush all pending but incomplete request/response pairs.
	if ( c?$redis_state && c$redis_state$current_response != 0 )
		{
		for ( r, info in c$redis_state$pending )
			{
			# We don't use pending elements at index 0.
			if ( r == 0 )
				next;
			Log::write(Redis::LOG, info);
			}
		}
	}
