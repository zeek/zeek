##! Log information about certificates while attempting to avoid duplicate
##! logging.

@load base/utils/directions-and-hosts
@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/cluster

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
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.
	const cert_tracking = LOCAL_HOSTS &redef;
	
	## The set of all known certificates to store for preventing duplicate 
	## logging. It can also be used from other scripts to 
	## inspect if a certificate has been seen in use. The string value 
	## in the set is for storing the DER formatted certificate' SHA1 hash.
	##
	## In cluster operation, this set is uniformly distributed across
	## proxy nodes.
	global certs: set[addr, string] &create_expire=1day &redef;
	
	## Event that can be handled to access the loggable record as it is sent
	## on to the logging framework.
	global log_known_certs: event(rec: CertsInfo);
}

event bro_init() &priority=5
	{
	Log::create_stream(Known::CERTS_LOG, [$columns=CertsInfo, $ev=log_known_certs, $path="known_certs"]);
	}

event known_cert_add(info: CertsInfo, hash: string)
	{
	if ( [info$host, hash] in Known::certs )
		return;

	add Known::certs[info$host, hash];
	Log::write(Known::CERTS_LOG, info);
	}

function cert_found(info: CertsInfo, hash: string)
	{
	@if ( Cluster::is_enabled() )
		local key = cat(info$host, hash);
		Cluster::publish_hrw(Cluster::proxy_pool, key, known_cert_add, info,
							 hash);
	@else
		event known_cert_add(info, hash);
	@endif
	}

event ssl_established(c: connection) &priority=3
	{
	if ( ! c$ssl?$cert_chain )
		return;
	
	if ( |c$ssl$cert_chain| < 1 )
		return;
	
	if ( ! c$ssl$cert_chain[0]?$x509 )
		return;

	local fuid = c$ssl$cert_chain_fuids[0];

	if ( ! c$ssl$cert_chain[0]?$sha1 )
		{
		Reporter::error(fmt("Certificate with fuid %s did not contain sha1 hash when checking for known certs. Aborting",
			fuid));
		return;
		}

	local host = c$id$resp_h;

	if ( ! addr_matches_host(host, cert_tracking) )
		return;

	local hash = c$ssl$cert_chain[0]$sha1;
	local cert = c$ssl$cert_chain[0]$x509$certificate;
	local info = CertsInfo($ts = network_time(), $host = host,
	                       $port_num = c$id$resp_p, $subject = cert$subject,
	                       $issuer_subject = cert$issuer,
	                       $serial = cert$serial);
	Known::cert_found(info, hash);
	}
