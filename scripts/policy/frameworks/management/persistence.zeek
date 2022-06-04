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

# Management agents and controllers don't have loggers, nor their configuration,
# so establish a similar one here:

function archiver_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$close);
	local base = fmt("%s__%s__%s__", ri$path, open_str, close_str);
	local rval = Log::RotationPath($file_basename=base);
	return rval;
	}

redef Log::default_rotation_interval = 1 hrs;
redef Log::enable_local_logging = T;
redef Log::enable_remote_logging = T;
redef Log::rotation_format_func = archiver_rotation_format_func;

redef LogAscii::enable_leftover_log_rotation = T;

@endif # ZEEK_MANAGEMENT_NODE

@endif # ZEEK_MANAGEMENT_TESTING
