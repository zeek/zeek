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

## Generic log metadata rendered into the filename that zeek-archiver may interpret.
## This is populated with a log_suffix entry within zeek_init() when multiple
## logger nodes are defined in cluster-layout.zeek.
global log_metadata: table[string] of string;

## Encode the given table as zeek-archiver understood metadata part.
function encode_log_metadata(tbl: table[string] of string): string
	{
	local metadata_vec: vector of string;
	for ( k, v in log_metadata )
		{
		if ( |v| == 0 )  # Assume concious decision to skip this entry.
			next;

		if ( /[,=]/ in k || /[,=]/ in v )
			{
			Reporter::warning(fmt("Invalid log_metadata: k='%s' v='%s'", k, v));
			next;
			}

		metadata_vec += fmt("%s=%s", k, v);
		}

	return join_string_vec(metadata_vec, ",");
	}

## This function will rotate logs in a format compatible with zeek-archiver.
## If you're using the Supervisor framework, this function will be used,
## if not, you can set :zeek:see:`Log::rotation_format_func` to this function.
function archiver_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$close);
	local base = fmt("%s__%s__%s__", ri$path, open_str, close_str);

	if ( |log_metadata| > 0 )
		base = fmt("%s%s__", base, encode_log_metadata(log_metadata));

	local rval = Log::RotationPath($file_basename=base);
	return rval;
	}

@if ( Supervisor::is_supervised() )

redef Log::default_rotation_dir = "log-queue";

redef Log::rotation_format_func = archiver_rotation_format_func;

redef LogAscii::enable_leftover_log_rotation = T;

event zeek_init()
	{
	if ( "log_suffix" in log_metadata )
		return;

	if ( Cluster::get_node_count(Cluster::LOGGER) > 1 )
		log_metadata["log_suffix"] = Cluster::node;
	}
@else

## Use the cluster's archive logging script.
redef Log::default_rotation_postprocessor_cmd = "archive-log";

@endif
