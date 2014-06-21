##! Generate notices when SSL/TLS connections use certificates or DH parameters
##! that have potentially unsafe key lengths.

@load base/protocols/ssl
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module SSL;

export {
	redef enum Notice::Type += {
		## Indicates that a server is using a potentially unsafe key.
		Weak_Key,
	};

	## The category of hosts you would like to be notified about which have
	## certificates that are going to be expiring soon.  By default, these
	## notices will be suppressed by the notice framework for 1 day after a particular
	## certificate has had a notice generated. Choices are: LOCAL_HOSTS, REMOTE_HOSTS,
	## ALL_HOSTS, NO_HOSTS
	const notify_weak_keys = LOCAL_HOSTS &redef;

	## The minimal key length in bits that is considered to be safe. Any shorter
	## (non-EC) key lengths will trigger the notice.
	const notify_minimal_key_length = 1024 &redef;

	## Warn if the DH key length is smaller than the certificate key length. This is
	## potentially unsafe because it gives a wrong impression of safety due to the
	## certificate key length. However, it is very common and cannot be avoided in some
	## settings (e.g. with old jave clients).
	const notify_dh_length_shorter_cert_length = T &redef;
}

# We check key lengths only for DSA or RSA certificates. For others, we do
# not know what is safe (e.g. EC is safe even with very short key lengths).
event ssl_established(c: connection) &priority=3
	{
	# If there are no certificates or we are not interested in the server, just return.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! addr_matches_host(c$id$resp_h, notify_weak_keys) ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local fuid = c$ssl$cert_chain_fuids[0];
	local cert = c$ssl$cert_chain[0]$x509$certificate;

	if ( !cert?$key_type || !cert?$key_length )
		return;

	if ( cert$key_type != "dsa" && cert$key_type != "rsa" )
		return;

	local key_length = cert$key_length;

	if ( key_length < notify_minimal_key_length )
		NOTICE([$note=Weak_Key,
			$msg=fmt("Host uses weak certificate with %d bit key", key_length),
			$conn=c, $suppress_for=1day,
			$identifier=cat(c$id$orig_h, c$id$orig_p, key_length)
		]);
	}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string) &priority=3
	{
	if ( ! addr_matches_host(c$id$resp_h, notify_weak_keys) )
		return;

	local key_length = |Ys| * 8; # key length in bits
 
	if ( key_length < notify_minimal_key_length )
		NOTICE([$note=Weak_Key,
			$msg=fmt("Host uses weak DH parameters with %d key bits", key_length),
			$conn=c, $suppress_for=1day,
			$identifier=cat(c$id$orig_h, c$id$orig_p, key_length)
		]);

	if ( notify_dh_length_shorter_cert_length &&
	     c?$ssl && c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 && c$ssl$cert_chain[0]?$x509 &&
	     c$ssl$cert_chain[0]$x509?$certificate && c$ssl$cert_chain[0]$x509$certificate?$key_type &&
	     (c$ssl$cert_chain[0]$x509$certificate$key_type == "rsa" ||
	       c$ssl$cert_chain[0]$x509$certificate$key_type == "dsa" ))
		{
		if ( c$ssl$cert_chain[0]$x509$certificate?$key_length &&
		     c$ssl$cert_chain[0]$x509$certificate$key_length > key_length )
			NOTICE([$note=Weak_Key,
				$msg=fmt("DH key length of %d bits is smaller certificate key length of %d bits",
					 key_length, c$ssl$cert_chain[0]$x509$certificate$key_length),
				$conn=c, $suppress_for=1day,
				$identifier=cat(c$id$orig_h, c$id$orig_p)
			       ]);
		}
	}
