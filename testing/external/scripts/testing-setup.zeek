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

# Prevent the version_info metric from being logged as it's not deterministic.
hook Telemetry::log_policy(rec: Telemetry::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$prefix == "zeek" && rec$name == "version_info" )
		break;
	}

# The IMAP analyzer includes absolute filenames in its error messages,
# exclude it for now from analyzer.log.
# https://github.com/zeek/zeek/issues/2659
redef Analyzer::Logging::ignore_analyzers += { Analyzer::ANALYZER_IMAP };
