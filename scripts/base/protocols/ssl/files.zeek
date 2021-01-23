@load ./main
@load base/utils/conn-ids
@load base/frameworks/files
@load base/files/x509

module SSL;

export {
	redef record Info += {
		## Chain of certificates offered by the server to validate its
		## complete signing chain.
		cert_chain: vector of Files::Info &optional;

		## An ordered vector of all certificate file unique IDs for the
		## certificates offered by the server.
		cert_chain_fuids: vector of string &optional &log;

		## Chain of certificates offered by the client to validate its
		## complete signing chain.
		client_cert_chain: vector of Files::Info &optional;

		## An ordered vector of all certificate file unique IDs for the
		## certificates offered by the client.
		client_cert_chain_fuids: vector of string &optional &log;

		## Subject of the X.509 certificate offered by the server.
		subject: string &log &optional;

		## Subject of the signer of the X.509 certificate offered by the
		## server.
		issuer: string &log &optional;

		## Subject of the X.509 certificate offered by the client.
		client_subject: string &log &optional;

		## Subject of the signer of the X.509 certificate offered by the
		## client.
		client_issuer: string &log &optional;

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

	local c: connection &is_set;	# &is_set to help static analysis

	for ( cid, c in f$conns )
		{
		if ( ! c?$ssl )
			return;
		}

	if ( ! c$ssl?$cert_chain )
		{
		c$ssl$cert_chain = vector();
		c$ssl$client_cert_chain = vector();
		c$ssl$cert_chain_fuids = string_vec();
		c$ssl$client_cert_chain_fuids = string_vec();
		}

	if ( f$is_orig )
		{
		c$ssl$client_cert_chain += f$info;
		c$ssl$client_cert_chain_fuids += f$id;
		}
	else
		{
		c$ssl$cert_chain += f$info;
		c$ssl$cert_chain_fuids += f$id;
		}
	}

event ssl_established(c: connection) &priority=6
	{
	# update subject and issuer information
	if ( c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 &&
	     c$ssl$cert_chain[0]?$x509 )
		{
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
