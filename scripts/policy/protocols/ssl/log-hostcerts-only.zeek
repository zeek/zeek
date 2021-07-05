##! When this script is loaded, only the host certificates (client and server)
##! will be logged to x509.log. Logging of all other certificates will be suppressed.

@load base/protocols/ssl
@load base/files/x509

module X509;

hook X509::log_policy(rec: X509::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( ! rec$host_cert )
		break;
	}
