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

		## An ordered vector of all certicate file unique IDs for the
		## certificates offered by the server.
		cert_chain_fuids: vector of string &optional &log;

		## Chain of certificates offered by the client to validate its
		## complete signing chain.
		client_cert_chain: vector of Files::Info &optional;

		## An ordered vector of all certicate file unique IDs for the
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
	set_session(c);

	local depth: count;

	if ( is_orig )
		{
		depth = c$ssl$client_depth;
		++c$ssl$client_depth;
		}
	else
		{
		depth = c$ssl$server_depth;
		++c$ssl$server_depth;
		}

	return cat(Analyzer::ANALYZER_SSL, c$start_time, is_orig, id_string(c$id), depth);
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
	for ( cid in f$conns )
		{
		if ( f$conns[cid]?$ssl )
			{
			local c = f$conns[cid];
			return cat(c$id$resp_h, ":", c$id$resp_p);
			}
		}

	return cat("Serial: ", f$info$x509$certificate$serial, " Subject: ",
		f$info$x509$certificate$subject, " Issuer: ",
		f$info$x509$certificate$issuer);
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_SSL,
	                         [$get_file_handle = SSL::get_file_handle,
	                          $describe        = SSL::describe_file]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( ! c?$ssl )
		return;

	if ( ! c$ssl?$cert_chain )
		{
		c$ssl$cert_chain = vector();
		c$ssl$client_cert_chain = vector();
		c$ssl$cert_chain_fuids = string_vec();
		c$ssl$client_cert_chain_fuids = string_vec();
		}

	if ( is_orig )
		{
		c$ssl$client_cert_chain[|c$ssl$client_cert_chain|] = f$info;
		c$ssl$client_cert_chain_fuids[|c$ssl$client_cert_chain_fuids|] = f$id;
		}
	else
		{
		c$ssl$cert_chain[|c$ssl$cert_chain|] = f$info;
		c$ssl$cert_chain_fuids[|c$ssl$cert_chain_fuids|] = f$id;
		}

	Files::add_analyzer(f, Files::ANALYZER_X509);
	# always calculate hashes. They are not necessary for base scripts
	# but very useful for identification, and required for policy scripts
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}

event ssl_established(c: connection) &priority=6
	{
	# update subject and issuer information
	if ( c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 )
		{
		c$ssl$subject = c$ssl$cert_chain[0]$x509$certificate$subject;
		c$ssl$issuer = c$ssl$cert_chain[0]$x509$certificate$issuer;
		}

	if ( c$ssl?$client_cert_chain && |c$ssl$client_cert_chain| > 0 )
		{
		c$ssl$client_subject = c$ssl$client_cert_chain[0]$x509$certificate$subject;
		c$ssl$client_issuer = c$ssl$client_cert_chain[0]$x509$certificate$issuer;
		}
	}
