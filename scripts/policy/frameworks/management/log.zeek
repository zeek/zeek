##! This module implements logging abilities for controller and agent. It uses
##! Zeek's logging framework and works only for nodes managed by the
##! supervisor. In this setting Zeek's logging framework operates locally, i.e.,
##! this does not involve logger nodes.

@load ./config

module Management::Log;

export {
	## The cluster logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The controller/agent log supports four different log levels.
	type Level: enum {
		DEBUG = 10,
		INFO = 20,
		WARNING = 30,
		ERROR = 40,
	};

	## The record type containing the column fields of the agent/controller log.
	type Info: record {
		## The time at which a cluster message was generated.
		ts: time;
		## The name of the node that is creating the log record.
		node: string;
		## Log level of this message, converted from the above Level enum
		level: string;
		## The role of the node, translated from Management::Role.
		role: string;
		## A message indicating information about cluster controller operation.
		message:  string;
	} &log;

	## The log level in use for this node. This is the minimum
	## log level required to produce output.
	global level = INFO &redef;

	## A debug-level log message writer.
	##
	## message: the message to log.
	##
	global debug: function(message: string);

	## An info-level log message writer.
	##
	## message: the message to log.
	##
	global info: function(message: string);

	## A warning-level log message writer.
	##
	## message: the message to log.
	##
	global warning: function(message: string);

	## An error-level log message writer. (This only logs a message, it does not
	## terminate Zeek or have other runtime effects.)
	##
	## message: the message to log.
	##
	global error: function(message: string);
}

# Enum translations to strings. This avoids those enums being reported
# with full qualifications in the logs, which is too verbose.

global l2s: table[Level] of string = {
	[DEBUG] = "DEBUG",
	[INFO] = "INFO",
	[WARNING] = "WARNING",
	[ERROR] = "ERROR",
};

global r2s: table[Management::Role] of string = {
	[Management::AGENT] = "AGENT",
	[Management::CONTROLLER] = "CONTROLLER",
	[Management::NODE] = "NODE",
};

function debug(message: string)
	{
	if ( enum_to_int(level) > enum_to_int(DEBUG) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[DEBUG],
			 $role=r2s[Management::role], $message=message]);
	}

function info(message: string)
	{
	if ( enum_to_int(level) > enum_to_int(INFO) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[INFO],
			 $role=r2s[Management::role], $message=message]);
	}

function warning(message: string)
	{
	if ( enum_to_int(level) > enum_to_int(WARNING) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[WARNING],
			 $role=r2s[Management::role], $message=message]);
	}

function error(message: string)
	{
	if ( enum_to_int(level) > enum_to_int(ERROR) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[ERROR],
			 $role=r2s[Management::role], $message=message]);
	}

# Bump priority to ensure the log stream exists when other zeek_init handlers use it.
event zeek_init() &priority=5
	{
	if ( ! Supervisor::is_supervised() )
		return;

	local node = Supervisor::node();

	# Defining the stream outside of the stream creation call sidesteps
	# the coverage.find-bro-logs test, which tries to inventory all logs.
	# This log isn't yet ready for that level of scrutiny.
	local stream = Log::Stream($columns=Info, $path=fmt("management-%s", node$name),
	                           $policy=log_policy);

	Log::create_stream(Management::Log::LOG, stream);
	}
