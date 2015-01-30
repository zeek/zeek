##! When this script is loaded, only the host certificates (client and server)
##! will be logged to x509.log. Logging of all other certificates will be suppressed.

@load base/protocols/ssl
@load base/files/x509

module X509;

export {
	redef record Info += {
	# Logging is suppressed if field is set to F
		logcert: bool &default=T;
	};
}

# We need both the Info and the fa_file record modified.
# The only instant when we have both, the connection and the
# file available without having to loop is in the file_over_new_connection
# event.
# When that event is raised, the x509 record in f$info (which is the only
# record the logging framework gets) is not yet available. So - we
# have to do this two times, sorry.
# Alternatively, we could place it info Files::Info first - but we would
# still have to copy it.
redef record fa_file += {
	logcert: bool &default=T;
};

function host_certs_only(rec: X509::Info): bool
	{
	return rec$logcert;
	}

event bro_init() &priority=2
	{
	local f = Log::get_filter(X509::LOG, "default");
	Log::remove_filter(X509::LOG, "default"); # disable default logging
	f$pred=host_certs_only; # and add our predicate
	Log::add_filter(X509::LOG, f);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=2
	{
	if ( ! c?$ssl )
		return;

	local chain: vector of string;

	if ( is_orig )
		chain = c$ssl$client_cert_chain_fuids;
	else
		chain = c$ssl$cert_chain_fuids;

	if ( |chain| == 0 )
		{
		Reporter::warning(fmt("Certificate not in chain? (fuid %s)", f$id));
		return;
		}

	# Check if this is the host certificate
	if ( f$id != chain[0] )
		f$logcert=F;
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=2
	{
	f$info$x509$logcert = f$logcert; # info record available, copy information.
	}
