##! This is the core Zeek script to support the notion of a cluster logger.
##!
##! The logger is passive (other Zeek instances connect to us), and once
##! connected the logger receives logs from other Zeek instances.
##! This script will be automatically loaded if necessary based on the
##! type of node being started.

##! This is where the cluster logger sets it's specific settings for other
##! frameworks and in the core.

@prefixes += cluster-logger

## Turn on local logging.
redef Log::enable_local_logging = T;

## Turn off remote logging since this is the logger and should only log here.
redef Log::enable_remote_logging = F;

## Log rotation interval.
redef Log::default_rotation_interval = 1 hrs;

## Alarm summary mail interval.
redef Log::default_mail_alarms_interval = 24 hrs;

@if ( Supervisor::is_supervised() )

redef Log::default_rotation_dir = "log-queue";

function supervisor_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$open);
	local prefix = fmt("%s__%s__%s__", ri$path, open_str, close_str);
	local rval = Log::RotationPath($file_prefix=prefix);
	return rval;
	}

redef Log::rotation_format_func = supervisor_rotation_format_func;

@else

## Use the cluster's archive logging script.
redef Log::default_rotation_postprocessor_cmd = "archive-log";

@endif
