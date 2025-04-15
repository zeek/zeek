# Sets some testing specific options.

@load external-ca-list

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

redef Analyzer::DebugLogging::include_confirmations = F;
redef Analyzer::DebugLogging::include_disabling = F;
