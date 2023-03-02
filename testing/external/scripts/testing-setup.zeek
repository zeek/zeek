# Sets some testing specific options.

@load external-ca-list

@ifdef ( SMTP::never_calc_md5 )
	# MDD5s can depend on libmagic output.
	redef SMTP::never_calc_md5 = T;
@endif

@ifdef ( LogAscii::use_json )
	# Don't start logging everything as JSON.
	# (json-logs.zeek activates this).
	redef LogAscii::use_json = F;
@endif

# Exclude process metrics, they are non-deterministic.
redef Telemetry::log_prefixes -= { "process" };

# Increase default telemetry.log 30x to reduce log size
# for traces spanning a long time period.
redef Telemetry::log_interval = 1800sec;

# Prevent the version_info metric from being logged as it's not deterministic.
hook Telemetry::log_policy(rec: Telemetry::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$prefix == "zeek" && rec$name == "version_info" )
		break;
	}

hook Telemetry::log_policy(rec: Telemetry::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$prefix != "zeek" )
		return;

	# Filter all event-handler-invocations entries from telemetry.log
	# except those having something to do with connection_*
	if ( rec$name == "event-handler-invocations" && /connection_.*/ !in cat(rec$label_values) )
		break;

	# Filter out the LoadedScripts stream due to platform dependent
	# difference in the scripts loaded, and also filter out Telemetry
	# log counts.
	if ( rec$name == /log-.*/ && /LoadedScripts::LOG|Telemetry::LOG/ in cat(rec$label_values) )
		break;
	}

# The IMAP analyzer includes absolute filenames in its error messages,
# exclude it for now from analyzer.log.
# https://github.com/zeek/zeek/issues/2659
redef Analyzer::Logging::ignore_analyzers += { Analyzer::ANALYZER_IMAP };
