##! This script can be used to log information about certificates while 
##! attempting to avoid duplicate logging.

@load base/utils/directions-and-hosts
@load base/protocols/ssl
@load protocols/ssl/cert-hash

module Known;

export {
	redef enum Log::ID += { CERTS_LOG };
	
	type CertsInfo: record {
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
	const cert_tracking = LOCAL_HOSTS &redef;
	
	## The set of all known certificates to store for preventing duplicate 
	## logging.  It can also be used from other scripts to 
	## inspect if a certificate has been seen in use. The string value 
	## in the set is for storing the DER formatted certificate's MD5 hash.
	global certs: set[addr, string] &create_expire=1day &synchronized &redef;
	
	global log_known_certs: event(rec: CertsInfo);
}

event bro_init() &priority=5
	{
	Log::create_stream(Known::CERTS_LOG, [$columns=CertsInfo, $ev=log_known_certs]);
	}

event x509_certificate(c: connection, cert: X509, is_server: bool, chain_idx: count, chain_len: count, der_cert: string) &priority=3
	{
	# We aren't tracking client certificates yet.
	if ( ! is_server ) return;
	# We are also only tracking the primary cert.
	if ( chain_idx != 0 ) return;
	
	local host = c$id$resp_h;
	if ( [host, c$ssl$cert_hash] !in certs && addr_matches_host(host, cert_tracking) )
		{
		add certs[host, cert$serial];
		Log::write(Known::CERTS_LOG, [$ts=network_time(), $host=host,
		                              $port_num=c$id$resp_p, $subject=cert$subject,
		                              $issuer_subject=cert$issuer,
		                              $serial=cert$serial,
		                              $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$cert_hash)]);
		}
	}
