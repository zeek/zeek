@load ./main
@load base/utils/conn-ids
@load base/frameworks/files
@load base/files/x509

module KRB;

export {
	redef record Info += {
		# Client certificate
		client_cert:		Files::Info &optional;
		# Subject of client certificate, if any
		client_cert_subject:	string &log &optional;
		# File unique ID of client cert, if any
		client_cert_fuid:	string &log &optional;

		# Server certificate
		server_cert:		Files::Info &optional;
		# Subject of server certificate, if any
		server_cert_subject:	string &log &optional;
		# File unique ID of server cert, if any
		server_cert_fuid:	string &log &optional;
	};

	## Default file handle provider for KRB.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for KRB.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	# Unused.  File handles are generated in the analyzer.
	return "";
	}

function describe_file(f: fa_file): string
	{
	if ( f$source != "KRB_TCP" && f$source != "KRB" )
		return "";

	if ( ! f?$info || ! f$info?$x509 || ! f$info$x509?$certificate )
		return "";

	# It is difficult to reliably describe a certificate - especially since
	# we do not know when this function is called (hence, if the data structures
	# are already populated).
	#
	# Just return a bit of our connection information and hope that that is good enough.
	for ( cid in f$conns )
		{
		if ( f$conns[cid]?$krb )
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
	Files::register_protocol(Analyzer::ANALYZER_KRB_TCP,
	                         [$get_file_handle = KRB::get_file_handle,
	                          $describe        = KRB::describe_file]);

	Files::register_protocol(Analyzer::ANALYZER_KRB,
	                         [$get_file_handle = KRB::get_file_handle,
	                          $describe        = KRB::describe_file]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( f$source != "KRB_TCP" && f$source != "KRB" )
		return;

	local info: Info;

	if ( ! c?$krb )
		{
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		}
	else
		info = c$krb;

	if ( is_orig )
		{
		info$client_cert = f$info;
		info$client_cert_fuid = f$id;
		}
	else
		{
		info$server_cert = f$info;
		info$server_cert_fuid = f$id;
		}

	c$krb = info;

	Files::add_analyzer(f, Files::ANALYZER_X509);
	# Always calculate hashes. They are not necessary for base scripts
	# but very useful for identification, and required for policy scripts
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}

function fill_in_subjects(c: connection)
	{
	if ( !c?$krb )
		return;

	if ( c$krb?$client_cert && c$krb$client_cert?$x509 && c$krb$client_cert$x509?$certificate )
		c$krb$client_cert_subject = c$krb$client_cert$x509$certificate$subject;

	if ( c$krb?$server_cert && c$krb$server_cert?$x509 && c$krb$server_cert$x509?$certificate )
		c$krb$server_cert_subject = c$krb$server_cert$x509$certificate$subject;
	}

event krb_error(c: connection, msg: Error_Msg)
	{
	fill_in_subjects(c);
	}

event krb_as_response(c: connection, msg: KDC_Response)
	{
	fill_in_subjects(c);
	}

event krb_tgs_response(c: connection, msg: KDC_Response)
	{
	fill_in_subjects(c);
	}

event connection_state_remove(c: connection)
	{
	fill_in_subjects(c);
	}
