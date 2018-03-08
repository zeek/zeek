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

# Use an alternate implementation of scripts that use broker data stores
# to avoid problems with the store expiration/timeouts (e.g. wall time
# versus packet time makes scripts operate differently on offline pcaps).
redef Known::use_host_store = F;
redef Known::use_cert_store = F;
redef Known::use_device_store = F;
redef Known::use_service_store = F;
