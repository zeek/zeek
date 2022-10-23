@load ./main
@load base/utils/conn-ids
@load base/frameworks/files
@load base/files/x509

module KRB;

export {
	redef record Info += {
		## Client certificate
		client_cert:		Files::Info &optional;
		## Subject of client certificate, if any
		client_cert_subject:	string &log &optional;
		## File unique ID of client cert, if any
		client_cert_fuid:	string &log &optional;

		## Server certificate
		server_cert:		Files::Info &optional;
		## Subject of server certificate, if any
		server_cert_subject:	string &log &optional;
		## File unique ID of server cert, if any
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
	# Just return a bit of our connection information and hope that is good enough.
	for ( cid, c in f$conns )
		{
		if ( c?$krb )
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

	set_session(c);

	if ( is_orig )
		{
		c$krb$client_cert = f$info;
		c$krb$client_cert_fuid = f$id;
		}
	else
		{
		c$krb$server_cert = f$info;
		c$krb$server_cert_fuid = f$id;
		}
	}

function fill_in_subjects(c: connection)
	{
	if ( ! c?$krb )
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

hook finalize_krb(c: connection) &priority=+5
	{
	fill_in_subjects(c);
	}
