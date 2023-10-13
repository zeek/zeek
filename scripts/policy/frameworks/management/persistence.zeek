##! Common adjustments for any kind of Zeek node when we run the Management
##! framework.

@load base/misc/installation
@load base/utils/paths

@load ./config

# For testing, keep persistent state local to the current working directory,
# and disable log rotation.
@if ( getenv("ZEEK_MANAGEMENT_TESTING") != "" )

redef Management::spool_dir = ".";
redef Management::state_dir = ".";
redef Log::default_rotation_interval = 0 secs;

@else

# For any kind of Zeek process we steer rotated logs awaiting archival into a
# queue directory in the spool. The name "log-queue" matches logger nodes' default
# config with the Supervisor; see base/frameworks/cluster/nodes/logger.zeek.
redef Log::default_rotation_dir = build_path(Management::get_spool_dir(), "log-queue");

@if ( getenv("ZEEK_MANAGEMENT_NODE") != "" )

# Management agents and controllers run their own logging setup, which we
# establish here. The controller serves as the central logger for any activity
# in the management infrastructure (i.e. including the controller, agents, and
# the Management shim running in cluster nodes).

# Have log writes go to the controller.
redef Broker::default_log_topic_prefix = Management::controller_topic_prefix + "/logs/";

function archiver_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$close);
	local base = fmt("%s__%s__%s__", ri$path, open_str, close_str);
	local rval = Log::RotationPath($file_basename=base);
	return rval;
	}

redef Log::default_rotation_interval = 1 hrs;
redef Log::enable_local_logging = Management::node_is_controller();
redef Log::enable_remote_logging = Management::node_is_agent();
redef Log::rotation_format_func = archiver_rotation_format_func;

redef LogAscii::enable_leftover_log_rotation = T;

@endif # ZEEK_MANAGEMENT_NODE

@endif # ZEEK_MANAGEMENT_TESTING
