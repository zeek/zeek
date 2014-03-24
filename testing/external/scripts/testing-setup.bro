# Sets some testing specific options.

@ifdef ( SMTP::never_calc_md5 )
	# MDD5s can depend on libmagic output.
	redef SMTP::never_calc_md5 = T;
@endif

@ifdef ( LogElasticSearch::server_host )
	# Set to empty so that logs-to-elasticsearch.bro doesn't try to setup
	#log forwarding to ES.
	redef LogElasticSearch::server_host = "";
@endif

@ifdef ( LogAscii::use_json )
	# Don't start logging everything as JSON.
	# (json-logs.bro activates this).
	redef LogAscii::use_json = F;
@endif
