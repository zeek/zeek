# Sets some testing specific options.

@load external-ca-list.bro

@ifdef ( SMTP::never_calc_md5 )
	# MDD5s can depend on libmagic output.
	redef SMTP::never_calc_md5 = T;
@endif

@ifdef ( LogAscii::use_json )
	# Don't start logging everything as JSON.
	# (json-logs.bro activates this).
	redef LogAscii::use_json = F;
@endif
