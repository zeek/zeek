@load base/utils/directions-and-hosts

module KnownCerts;

export {
	redef enum Log::ID += { KNOWN_CERTS };
	
	type Info: record {
		## The timestamp when the certificate was detected.
		ts:             time   &log;
		## The address that offered the certificate.
		host:           addr   &log;
		## If the certificate was handed out by a server, this is the 
		## port that the server was listening on.
		port_num:       port   &log &optional;
		## Certificate subject.
		subject:        string &log &optional;
		## Certificate issuer subject.
		issuer_subject: string &log &optional;
		## Serial number for the certificate.
		serial:         string &log &optional;
	};
	
	## The certificates whose existence should be logged and tracked.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
	const asset_tracking = LOCAL_HOSTS &redef;
	
	## The set of all known certificates to store for preventing duplicate 
	## logging.  It can also be used from other scripts to 
	## inspect if a certificate has been seen in use. The string value 
	## in the set is for storing the certificate's serial number.
	global known_certs: set[addr, string] &create_expire=1day &synchronized &redef;
	
	global log_known_certs: event(rec: Info);
}

event bro_init()
	{
	Log::create_stream(KNOWN_CERTS, [$columns=Info, $ev=log_known_certs]);
	}

event x509_certificate(c: connection, cert: X509, is_server: bool, chain_idx: count, chain_len: count, der_cert: string)
	{
	# We aren't tracking client certificates yet.
	if ( ! is_server ) return;
	# We are also only tracking the primary cert.
	if ( chain_idx != 0 ) return;
		
	local host = c$id$resp_h;
	if ( [host, cert$serial] !in known_certs && addr_matches_host(host, asset_tracking) )
		{
		add known_certs[host, cert$serial];
		Log::write(KNOWN_CERTS, [$ts=network_time(), $host=host,
		                         $port_num=c$id$resp_p, $subject=cert$subject,
		                         $issuer_subject=cert$issuer,
		                         $serial=cert$serial]);
		}
	}
