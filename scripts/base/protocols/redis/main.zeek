@load base/protocols/conn/removal-hooks
@load base/frameworks/signatures

@load ./spicy-events

module Redis;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register Redis for.
	const ports = {6379/tcp} &redef;

	## Record type containing the column fields of the Redis log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The Redis command.
		cmd: Command &log;
		## If the command was successful. Only set if the server responded.
		success: bool &log &optional;
		## The reply for the command.
		reply: ReplyData &log &optional;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	global finalize_redis: Conn::RemovalHook;

	## Which numbered commands should not expect a reply due to CLIENT REPLY commands.
	## These commands may simply skip one, or they may turn off replies then later
	## reenable them. Thus, the end of the interval is optional.
	type NoReplyRange: record {
		begin: count;
		end: count &optional;
	};

	type RESPVersion: enum {
		RESP2,
		RESP3
	};

	type State: record {
		## Pending commands.
		pending: table[count] of Info;
		## Current command in the pending queue.
		current_command: count &default=0;
		## Current reply in the pending queue.
		current_reply: count &default=0;
		## Ranges where we do not expect a reply due to CLIENT REPLY commands.
		## Each range is one or two elements, one meaning it's unbounded, two meaning
		## it begins at one and ends at the second.
		no_reply_ranges: vector of NoReplyRange;
		## The command indexes (from current_command and current_reply) that will
		## not get responses no matter what.
		skip_commands: set[count];
		## We store if this analyzer had a violation to avoid logging if so.
		## This should not be super necessary, but worth a shot.
		violation: bool &default=F;
		## If we are in "subscribed" mode
		subscribed_mode: bool &default=F;
		## The RESP version
		resp_version: RESPVersion &default=RESP2;
	};

	# Redis specifically mentions 10k commands as a good pipelining threshold, so
	# we'll piggyback on that.
	option max_pending_commands = 10000;

	# These commands enter subscribed mode
	global enter_subscribed_mode = [RedisCommand_PSUBSCRIBE,
	    RedisCommand_SSUBSCRIBE, RedisCommand_SUBSCRIBE];

	# These commands exit subscribed mode
	global exit_subscribed_mode = [RedisCommand_RESET, RedisCommand_QUIT];

	# These commands don't expect a response (ever) - their replies are out of band.
	global no_response_commands = [RedisCommand_PSUBSCRIBE,
	    RedisCommand_PUNSUBSCRIBE, RedisCommand_SSUBSCRIBE,
	    RedisCommand_SUBSCRIBE, RedisCommand_SUNSUBSCRIBE,
	    RedisCommand_UNSUBSCRIBE];
}

redef record connection += {
	redis: Info &optional;
	redis_state: State &optional;
};

redef likely_server_ports += {ports};

event zeek_init() &priority=5
	{
	Log::create_stream(Redis::LOG, [$columns=Info, $path="redis",
	    $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_REDIS, ports);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag,
    info: AnalyzerViolationInfo)
	{
	if ( atype == Analyzer::ANALYZER_REDIS && info?$c && info$c?$redis_state )
		{
		info$c$redis_state$violation = T;
		}
	}

function new_redis_info(c: connection): Info
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
		current = c$redis_state$current_command;
	else
		current = c$redis_state$current_reply;

	if ( current !in c$redis_state$pending )
		c$redis_state$pending[current] = new_redis_info(c);

	c$redis = c$redis_state$pending[current];
	}

## Returns whether the last "no reply" interval is not still open.
function is_last_interval_closed(c: connection): bool
	{
	return |c$redis_state$no_reply_ranges| == 0 ||
	    c$redis_state$no_reply_ranges[-1]?$end;
	}

event hello_command(c: connection, hello: HelloCommand)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	if ( hello?$requested_resp_version && hello$requested_resp_version == "3" )
		c$redis_state$resp_version = RESP3;
	}

event command(c: connection, cmd: Command)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	if ( max_pending_commands > 0
	    && |c$redis_state$pending| > max_pending_commands )
		{
		Reporter::conn_weird("Redis_excessive_pipelining", c);
		# Delete the current state and restart later. We'll be in a weird state, but
		# really we want to abort. I don't quite get how to register this as a
		# violation. :)
		delete c$redis_state;
		return;
		}

	++c$redis_state$current_command;

	if ( cmd?$known )
		{
		if ( c$redis_state$resp_version == RESP2 )
			{
			local should_enter = cmd$known in enter_subscribed_mode;
			local should_exit = cmd$known in exit_subscribed_mode;
			c$redis_state$subscribed_mode = should_enter && ! should_exit;

			# It's weird if it's in both - in the future users may be able to add that
			if ( should_enter && should_exit )
				Reporter::conn_weird("Redis_command_enter_exit_subscribed_mode", c, cat(
				    cmd$known));
			}
		if ( cmd$known in no_response_commands || c$redis_state$subscribed_mode )
			{
			add c$redis_state$skip_commands[c$redis_state$current_command];
			}
		}

	# CLIENT commands can skip a number of replies and may be used with
	# pipelining. We need special logic in order to track the command/reply
	# pairs.
	if ( cmd?$known && cmd$known == RedisCommand_CLIENT )
		{
		# All 3 CLIENT commands we care about have 3 elements
		if ( |cmd$raw| == 3 )
			{
			if ( to_lower(cmd$raw[2]) == "on" )
				{
				# If the last range is open, close it here. Otherwise, noop
				if ( |c$redis_state$no_reply_ranges| > 0 )
					{
					local range = c$redis_state$no_reply_ranges[-1];
					if ( ! range?$end )
						{
						range$end = c$redis_state$current_command;
						}
					}
				}
			if ( to_lower(cmd$raw[2]) == "off" )
				{
				# Only add a new interval if the last one is closed
				if ( is_last_interval_closed(c) )
					{
					c$redis_state$no_reply_ranges += NoReplyRange(
					    $begin=c$redis_state$current_command);
					}
				}
			if ( to_lower(cmd$raw[2]) == "skip" )
				{
				if ( is_last_interval_closed(c) )
					# It skips this one and the next one
					c$redis_state$no_reply_ranges += NoReplyRange(
					    $begin=c$redis_state$current_command, $end=c$redis_state$current_command + 2);
				}
			}
		}

	set_state(c, T);

	c$redis$cmd = cmd;
	}

## Gets the next reply number based on a connection. This is necessary since
## some replies may have been skipped.
function reply_num(c: connection): count
	{
	local resp_num = c$redis_state$current_reply + 1;
	local result = resp_num;
	for ( i in c$redis_state$no_reply_ranges )
		{
		local range = c$redis_state$no_reply_ranges[i];
		if ( ! range?$end && resp_num > range$begin )
			{ } # TODO: This is necessary if not using pipelining
		if ( range?$end && resp_num >= range$begin && resp_num < range$end )
			result = range$end;
		}

	# Account for commands that don't expect a response
	while ( result in c$redis_state$skip_commands )
		{
		delete c$redis_state$skip_commands[result];
		result += 1;
		}

	return result;
	}

# Logs up to and including the last seen command from the last reply
function log_from(c: connection, previous_reply_num: count)
	{
	# Log each of the pending replies to this point - we will not go
	# back.
	while ( previous_reply_num < c$redis_state$current_reply )
		{
		if ( previous_reply_num == 0 )
			{
			++previous_reply_num;
			next;
			}

		if ( previous_reply_num in c$redis_state$pending &&
		    c$redis_state$pending[previous_reply_num]?$cmd )
			{
			Log::write(Redis::LOG, c$redis_state$pending[previous_reply_num]);
			delete c$redis_state$pending[previous_reply_num];
			}
		previous_reply_num += 1;
		}
	# Log this one if we have the command and reply
	if ( c$redis?$cmd )
		{
		Log::write(Redis::LOG, c$redis);
		delete c$redis_state$pending[c$redis_state$current_reply];
		}
	}

event reply(c: connection, data: ReplyData)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	# If the server is talking in RESP3, mark accordingly, even if we didn't see HELLO
	if ( data$min_protocol_version == 3 )
		{
		c$redis_state$resp_version = RESP3;
		c$redis_state$subscribed_mode = F;
		}

	if ( c$redis_state$subscribed_mode )
		{
		event server_push(c, data);
		return;
		}

	local previous_reply_num = c$redis_state$current_reply;
	c$redis_state$current_reply = reply_num(c);
	set_state(c, F);

	c$redis$reply = data;
	c$redis$success = T;
	log_from(c, previous_reply_num);

	# Tidy up the skip_commands when it's up to date
	if ( c$redis_state$current_command == c$redis_state$current_reply )
		clear_table(c$redis_state$skip_commands);
	}

event error(c: connection, data: ReplyData)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	local previous_reply_num = c$redis_state$current_reply;
	c$redis_state$current_reply = reply_num(c);
	set_state(c, F);

	c$redis$reply = data;
	c$redis$success = F;
	log_from(c, previous_reply_num);
	}

hook finalize_redis(c: connection)
	{
	if ( c$redis_state$violation )
		{
		# If there's a violation, don't log the remaining parts, just return.
		return;
		}
	# Flush all pending but incomplete command/reply pairs.
	if ( c?$redis_state && c$redis_state$current_reply != 0 )
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
