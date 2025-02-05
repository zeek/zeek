# Sets some testing specific options.

@load external-ca-list

@load protocols/conn/failed-service-logging

@ifdef ( SMTP::never_calc_md5 )
	# MDD5s can depend on libmagic output.
	redef SMTP::never_calc_md5 = T;
@endif

@ifdef ( LogAscii::use_json )
	# Don't start logging everything as JSON.
	# (json-logs.zeek activates this).
	redef LogAscii::use_json = F;
@endif

# The IMAP analyzer includes absolute filenames in its error messages,
# exclude it for now from analyzer.log.
# https://github.com/zeek/zeek/issues/2659
redef Analyzer::Logging::ignore_analyzers += { Analyzer::ANALYZER_IMAP };
