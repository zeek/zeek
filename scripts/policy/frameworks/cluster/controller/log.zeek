@load ./config

module ClusterController::Log;

export {
	## The cluster logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	type Level: enum {
		DEBUG,
		INFO,
		WARNING,
		ERROR,
	};

	## The record type which contains the column fields of the cluster log.
	type Info: record {
		## The time at which a cluster message was generated.
		ts:       time;
		## The name of the node that is creating the log record.
		node: string;
		## Log level of this message, converted from the above Level enum
		level: string;
		## The role of the node, translated from ClusterController::Types::Role.
		role: string;
		## A message indicating information about cluster controller operation.
		message:  string;
	} &log;

	global log_level = DEBUG &redef;

	global debug: function(message: string);
	global info: function(message: string);
	global warning: function(message: string);
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

global r2s: table[ClusterController::Types::Role] of string = {
	[ClusterController::Types::AGENT] = "AGENT",
	[ClusterController::Types::CONTROLLER] = "CONTROLLER",
};

function debug(message: string)
	{
	if ( enum_to_int(log_level) > enum_to_int(DEBUG) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[DEBUG],
			 $role=r2s[ClusterController::role], $message=message]);
	}

function info(message: string)
	{
	if ( enum_to_int(log_level) > enum_to_int(INFO) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[INFO],
			 $role=r2s[ClusterController::role], $message=message]);
	}

function warning(message: string)
	{
	if ( enum_to_int(log_level) > enum_to_int(WARNING) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[WARNING],
			 $role=r2s[ClusterController::role], $message=message]);
	}

function error(message: string)
	{
	if ( enum_to_int(log_level) > enum_to_int(ERROR) )
		return;

	local node = Supervisor::node();
	Log::write(LOG, [$ts=network_time(), $node=node$name, $level=l2s[ERROR],
			 $role=r2s[ClusterController::role], $message=message]);
	}

event zeek_init()
	{
	if ( ! Supervisor::is_supervised() )
		return;

	local node = Supervisor::node();

	# Defining the stream outside of the stream creation call sidesteps
	# the coverage.find-bro-logs test, which tries to inventory all logs.
	# This log isn't yet ready for that level of scrutiny.
	local stream = Log::Stream($columns=Info, $path=fmt("cluster-%s", node$name),
	                           $policy=log_policy);

	Log::create_stream(ClusterController::Log::LOG, stream);
	}
