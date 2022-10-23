@load ./main
@load base/utils/conn-ids
@load base/frameworks/files
@load base/files/x509

module SSL;

export {
	## Set this to true to include the server certificate subject and
	## issuer from the SSL log file. This information is still available
	## in x509.log.
	const log_include_server_certificate_subject_issuer = F &redef;

	## Set this to true to include the client certificate subject
	## and issuer in the SSL logfile. This information is rarely present
	## and probably only interesting in very specific circumstances
	const log_include_client_certificate_subject_issuer = F &redef;

	redef record Info += {
		## Chain of certificates offered by the server to validate its
		## complete signing chain.
		cert_chain: vector of Files::Info &optional;

		## An ordered vector of all certificate fingerprints for the
		## certificates offered by the server.
		cert_chain_fps: vector of string &optional &log;

		## Chain of certificates offered by the client to validate its
		## complete signing chain.
		client_cert_chain: vector of Files::Info &optional;

		## An ordered vector of all certificate fingerprints for the
		## certificates offered by the client.
		client_cert_chain_fps: vector of string &optional &log;

		## Subject of the X.509 certificate offered by the server.
		subject: string &log &optional;

		## Issuer of the signer of the X.509 certificate offered by the
		## server.
		issuer: string &log &optional;

		## Subject of the X.509 certificate offered by the client.
		client_subject: string &log &optional;

		## Subject of the signer of the X.509 certificate offered by the
		## client.
		client_issuer: string &log &optional;

		## Set to true if the hostname sent in the SNI matches the certificate.
		## Set to false if they do not match. Unset if the client did not send
		## an SNI.
		sni_matches_cert: bool &log &optional;

		## Current number of certificates seen from either side. Used
		## to create file handles.
		server_depth: count &default=0;
		client_depth: count &default=0;
	};

	## Default file handle provider for SSL.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for SSL.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	# Unused.  File handles are generated in the analyzer.
	return "";
	}

function describe_file(f: fa_file): string
	{
	if ( f$source != "SSL" || ! f?$info || ! f$info?$x509 || ! f$info$x509?$certificate )
		return "";

	# It is difficult to reliably describe a certificate - especially since
	# we do not know when this function is called (hence, if the data structures
	# are already populated).
	#
	# Just return a bit of our connection information and hope that that is good enough.
	for ( cid, c in f$conns )
		{
		if ( c?$ssl )
			{
			return cat(c$id$resp_h, ":", c$id$resp_p);
			}
		}

	return cat("Serial: ", f$info$x509$certificate$serial, " Subject: ",
		f$info$x509$certificate$subject, " Issuer: ",
		f$info$x509$certificate$issuer);
	}

event zeek_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_SSL,
	                         [$get_file_handle = SSL::get_file_handle,
	                          $describe        = SSL::describe_file]);

	Files::register_protocol(Analyzer::ANALYZER_DTLS,
	                         [$get_file_handle = SSL::get_file_handle,
	                          $describe        = SSL::describe_file]);


	local ssl_filter = Log::get_filter(SSL::LOG, "default");
	if ( ssl_filter$name != "<not found>" )
		{
		if ( ! ssl_filter?$exclude )
			ssl_filter$exclude = set();
		if ( ! log_include_server_certificate_subject_issuer )
			{
			add ssl_filter$exclude["subject"];
			add ssl_filter$exclude["issuer"];
			}
		if ( ! log_include_client_certificate_subject_issuer )
			{
			add ssl_filter$exclude["client_subject"];
			add ssl_filter$exclude["client_issuer"];
			}
		Log::add_filter(SSL::LOG, ssl_filter);
		}
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( ! f?$conns || |f$conns| != 1 )
		return;

	if ( ! f?$info || ! f$info?$mime_type )
		return;

	if ( ! ( f$info$mime_type == "application/x-x509-ca-cert" || f$info$mime_type == "application/x-x509-user-cert"
	         || f$info$mime_type == "application/pkix-cert" ) )
		return;

	local c: connection &is_assigned;	# to help static analysis

	for ( cid, c in f$conns )
		{
		if ( ! c?$ssl )
			return;
		}

	if ( ! c$ssl?$cert_chain )
		{
		c$ssl$cert_chain = vector();
		c$ssl$client_cert_chain = vector();
		c$ssl$cert_chain_fps = string_vec();
		c$ssl$client_cert_chain_fps = string_vec();
		}

	# Note - for SSL connections, is_orig indicates client/server, not necessary originator/responder.
	if ( f$is_orig )
		c$ssl$client_cert_chain += f$info;
	else
		c$ssl$cert_chain += f$info;
	}

hook ssl_finishing(c: connection) &priority=20
	{
	if ( c$ssl?$cert_chain)
		for ( i in c$ssl$cert_chain )
			if ( c$ssl$cert_chain[i]?$x509 && c$ssl$cert_chain[i]$x509?$fingerprint )
				c$ssl$cert_chain_fps += c$ssl$cert_chain[i]$x509$fingerprint;

	if ( c$ssl?$client_cert_chain )
		for ( i in c$ssl$client_cert_chain )
			if ( c$ssl$client_cert_chain[i]?$x509 && c$ssl$client_cert_chain[i]$x509?$fingerprint )
				c$ssl$client_cert_chain_fps += c$ssl$client_cert_chain[i]$x509$fingerprint;

	if ( c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 &&
	     c$ssl$cert_chain[0]?$x509 )
		{
		if ( c$ssl?$server_name )
			{
			if ( x509_check_cert_hostname(c$ssl$cert_chain[0]$x509$handle, c$ssl$server_name) != "" )
				c$ssl$sni_matches_cert = T;
			else
				c$ssl$sni_matches_cert = F;
			}

		c$ssl$subject = c$ssl$cert_chain[0]$x509$certificate$subject;
		c$ssl$issuer = c$ssl$cert_chain[0]$x509$certificate$issuer;
		}

	if ( c$ssl?$client_cert_chain && |c$ssl$client_cert_chain| > 0 &&
	     c$ssl$client_cert_chain[0]?$x509 )
		{
		c$ssl$client_subject = c$ssl$client_cert_chain[0]$x509$certificate$subject;
		c$ssl$client_issuer = c$ssl$client_cert_chain[0]$x509$certificate$issuer;
		}
	}
