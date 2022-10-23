##! Generate notices when SSL/TLS connections use certificates, DH parameters,
##! or cipher suites that are deemed to be insecure.

@load base/protocols/ssl
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module SSL;

export {
	redef enum Notice::Type += {
		## Indicates that a server is using a potentially unsafe key.
		Weak_Key,
		## Indicates that a server is using a potentially unsafe version
		Old_Version,
		## Indicates that a server is using a potentially unsafe cipher
		Weak_Cipher
	};

	## The category of hosts you would like to be notified about which are using weak
	## keys/ciphers/protocol_versions.  By default, these notices will be suppressed
	## by the notice framework for 1 day after a particular host has had a notice
	## generated. Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
	option notify_weak_keys = LOCAL_HOSTS;

	## The minimal key length in bits that is considered to be safe. Any shorter
	## (non-EC) key lengths will trigger a notice.
	option notify_minimal_key_length = 2048;

	## Warn if the DH key length is smaller than the certificate key length. This is
	## potentially unsafe because it gives a wrong impression of safety due to the
	## certificate key length. However, it is very common and cannot be avoided in some
	## settings (e.g. with old java clients).
	option notify_dh_length_shorter_cert_length = T;

	## Warn if a server negotiates a SSL session with a protocol version smaller than
	## the specified version. By default, the minimal version is TLSv10 because SSLv2
	## and v3 have serious security issued.
	## See https://tools.ietf.org/html/draft-thomson-sslv3-diediedie-00
	## To disable, set to SSLv20
	option tls_minimum_version = TLSv10;

	## Warn if a server negotiates an unsafe cipher suite. By default, we only warn when
	## encountering old export cipher suites, or RC4 (see RFC7465).
	option unsafe_ciphers_regex = /(_EXPORT_)|(_RC4_)/;
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

	local fuid = c$ssl$cert_chain[0]$fuid;
	local cert = c$ssl$cert_chain[0]$x509$certificate;
	local hash = c$ssl$cert_chain[0]$x509$fingerprint;

	if ( !cert?$key_type || !cert?$key_length )
		return;

	if ( cert$key_type != "dsa" && cert$key_type != "rsa" )
		return;

	local key_length = cert$key_length;

	if ( key_length < notify_minimal_key_length )
		NOTICE([$note=Weak_Key,
			$msg=fmt("Host uses weak certificate with %d bit key", key_length),
			$conn=c, $suppress_for=1day,
			$identifier=cat(c$id$resp_h, c$id$resp_p, hash, key_length),
			$sub=fmt("Subject: %s", cert$subject),
			$file_desc=fmt("Fingerprint: %s", hash)
		]);
	}

# Check for old SSL versions and weak connection keys
event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=3
	{
	if ( ! addr_matches_host(c$id$resp_h, notify_weak_keys) )
		return;

	if ( version < tls_minimum_version )
		{
		local minimum_string = version_strings[tls_minimum_version];
		local host_string = version_strings[version];
		NOTICE([$note=Old_Version,
			$msg=fmt("Host uses protocol version %s which is lower than the safe minimum %s", host_string, minimum_string),
			$conn=c, $suppress_for=1day,
			$identifier=cat(c$id$resp_h, c$id$resp_p)
		]);
		}

	if ( unsafe_ciphers_regex in c$ssl$cipher )
		NOTICE([$note=Weak_Cipher,
			$msg=fmt("Host established connection using unsafe cipher suite %s", c$ssl$cipher),
			$conn=c, $suppress_for=1day,
			$identifier=cat(c$id$resp_h, c$id$resp_p, c$ssl$cipher)
		]);
	}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string) &priority=3
	{
	if ( ! addr_matches_host(c$id$resp_h, notify_weak_keys) )
		return;

	local key_length = |p| * 8; # length of the used prime number in bits

	if ( key_length < notify_minimal_key_length )
		NOTICE([$note=Weak_Key,
			$msg=fmt("Host uses weak DH parameters with %d key bits", key_length),
			$conn=c, $suppress_for=1day,
			$identifier=cat(c$id$resp_h, c$id$resp_p, key_length)
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
				$identifier=cat(c$id$resp_h, c$id$resp_p)
			       ]);
		}
	}
