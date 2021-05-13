##! Generate notices when X.509 certificates over SSL/TLS are expired or 
##! going to expire soon based on the date and time values stored within the
##! certificate.

@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module SSL;

export {
	redef enum Notice::Type += {
		## Indicates that a certificate's NotValidAfter date has lapsed
		## and the certificate is now invalid.
		Certificate_Expired,
		## Indicates that a certificate is going to expire within
		## :zeek:id:`SSL::notify_when_cert_expiring_in`.
		Certificate_Expires_Soon,
		## Indicates that a certificate's NotValidBefore date is future
		## dated.
		Certificate_Not_Valid_Yet,
	};

	## The category of hosts you would like to be notified about which have
	## certificates that are going to be expiring soon.  By default, these
	## notices will be suppressed by the notice framework for 1 day after
	## a particular certificate has had a notice generated.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
	option notify_certs_expiration = LOCAL_HOSTS;

	## The time before a certificate is going to expire that you would like
	## to start receiving :zeek:enum:`SSL::Certificate_Expires_Soon` notices.
	option notify_when_cert_expiring_in = 30days;
}

event ssl_established(c: connection) &priority=3
	{
	# If there are no certificates or we are not interested in the server, just return.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! addr_matches_host(c$id$resp_h, notify_certs_expiration) ||
	     ! c$ssl$cert_chain[0]?$x509 || ! c$ssl$cert_chain[0]?$sha1 )
		return;

	local fuid = c$ssl$cert_chain[0]$fuid;
	local cert = c$ssl$cert_chain[0]$x509$certificate;
	local hash = c$ssl$cert_chain[0]$sha1;

	if ( cert$not_valid_before > network_time() )
		NOTICE([$note=Certificate_Not_Valid_Yet,
		        $conn=c, $suppress_for=1day,
		        $msg=fmt("Certificate %s isn't valid until %T", cert$subject, cert$not_valid_before),
		        $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
		        $fuid=fuid]);

	else if ( cert$not_valid_after < network_time() )
		NOTICE([$note=Certificate_Expired,
		        $conn=c, $suppress_for=1day,
		        $msg=fmt("Certificate %s expired at %T", cert$subject, cert$not_valid_after),
		        $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
		        $fuid=fuid]);

	else if ( cert$not_valid_after - notify_when_cert_expiring_in < network_time() )
		NOTICE([$note=Certificate_Expires_Soon,
		        $msg=fmt("Certificate %s is going to expire at %T", cert$subject, cert$not_valid_after),
		        $conn=c, $suppress_for=1day,
		        $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
		        $fuid=fuid]);
	}
