##! Generate notices when X.509 certificates over SSL/TLS are expired or 
##! going to expire soon based on the date and time values stored within the
##! certificate.

@load base/protocols/ssl
@load base/frameworks/notice
@load base/utils/directions-and-hosts

@load protocols/ssl/cert-hash

module SSL;

export {
	redef enum Notice::Type += {
		## Indicates that a certificate's NotValidAfter date has lapsed
		## and the certificate is now invalid.
		Certificate_Expired,
		## Indicates that a certificate is going to expire within 
		## :bro:id:`SSL::notify_when_cert_expiring_in`.
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
	const notify_certs_expiration = LOCAL_HOSTS &redef;
	
	## The time before a certificate is going to expire that you would like
	## to start receiving :bro:enum:`SSL::Certificate_Expires_Soon` notices.
	const notify_when_cert_expiring_in = 30days &redef;
}

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string) &priority=3
	{
	# If this isn't the host cert or we aren't interested in the server, just return.
	if ( is_orig || 
		 chain_idx != 0 ||
		 ! c$ssl?$cert_hash || 
		 ! addr_matches_host(c$id$resp_h, notify_certs_expiration) )
		return;
	
	if ( cert$not_valid_before > network_time() )
		NOTICE([$note=Certificate_Not_Valid_Yet,
		        $conn=c, $suppress_for=1day,
		        $msg=fmt("Certificate %s isn't valid until %T", cert$subject, cert$not_valid_before),
		        $identifier=cat(c$id$resp_h, c$id$resp_p, c$ssl$cert_hash)]);
	
	else if ( cert$not_valid_after < network_time() )
		NOTICE([$note=Certificate_Expired,
		        $conn=c, $suppress_for=1day,
		        $msg=fmt("Certificate %s expired at %T", cert$subject, cert$not_valid_after),
		        $identifier=cat(c$id$resp_h, c$id$resp_p, c$ssl$cert_hash)]);
	
	else if ( cert$not_valid_after - notify_when_cert_expiring_in < network_time() )
		NOTICE([$note=Certificate_Expires_Soon,
		        $msg=fmt("Certificate %s is going to expire at %T", cert$subject, cert$not_valid_after),
		        $conn=c, $suppress_for=1day,
		        $identifier=cat(c$id$resp_h, c$id$resp_p, c$ssl$cert_hash)]);
	}
