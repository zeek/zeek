# Sets some testing specific options.

@load external-ca-list
@load external-ct-list

@load protocols/conn/failed-service-logging
redef DPD::track_removed_services_in_connection=T;

@ifdef ( SMTP::never_calc_md5 )
	# MDD5s can depend on libmagic output.
	redef SMTP::never_calc_md5 = T;
@endif

@ifdef ( LogAscii::use_json )
	# Don't start logging everything as JSON.
	# (json-logs.zeek activates this).
	redef LogAscii::use_json = F;
@endif

# The tests don't load intel data and so all Intel event groups are disabled
# due to intel/seen/manage-event-groups being loaded by default. Disable that
# functionality by default to cover execution in the intel/seen scripts.
redef Intel::manage_seen_event_groups = F;

# The IMAP analyzer includes absolute filenames in its error messages,
# exclude it for now from analyzer.log.
# https://github.com/zeek/zeek/issues/2659
redef Analyzer::DebugLogging::ignore_analyzers += { Analyzer::ANALYZER_IMAP };
redef Analyzer::DebugLogging::include_confirmations = F;
redef Analyzer::DebugLogging::include_disabling = F;
