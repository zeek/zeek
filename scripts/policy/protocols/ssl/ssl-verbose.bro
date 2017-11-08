##! More verbose version of the base SSL analysis script. This script
##! additionally logs client and server randoms, key exchange values, signatures,
##! and certificates hashes.

@load base/protocols/ssl
@load base/files/x509
@load base/utils/directions-and-hosts

module SSL;

export {
	redef record Info += {
		# ClientHello
		client_random: string &log &optional;
		client_cipher_suites: string &log &optional;

		# ServerHello
		server_random: string &log &optional;

		# ServerKeyExchange
		server_dh_p: string &log &optional;
		server_dh_q: string &log &optional;
		server_dh_Ys: string &log &optional;
		server_ecdh_point: string &log &optional;
		server_signature: string &log &optional;

		# ServerCertificate
		server_cert_sha1: string &log &optional;

		# ClientKeyExchange
		client_rsa_pms: string &log &optional;
		client_dh_Yc: string &log &optional;
		client_ecdh_point: string &log &optional;
	};

	## Control if host certificates offered by the defined hosts
	## will be written to the PEM certificates file.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.
	const extract_certs_pem = ALL_HOSTS &redef;
}

# This is an internally maintained variable to prevent relogging of
# certificates that have already been seen.  It is indexed on an sha1 sum of
# the certificate.
global extracted_certs: set[string] = set() &read_expire=1hr &redef;

event ssl_established(c: connection) &priority=5
	{
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	if ( ! addr_matches_host(c$id$resp_h, extract_certs_pem) )
		return;

	local hash = c$ssl$cert_chain[0]$sha1;
	local cert = c$ssl$cert_chain[0]$x509$handle;

	c$ssl$server_cert_sha1 = hash;

	if ( hash in extracted_certs )
		# If we already extracted this cert, don't do it again.
		return;

	add extracted_certs[hash];
	local filename = Site::is_local_addr(c$id$resp_h) ? "certs-local.pem" : "certs-remote.pem";
	local outfile = open_for_append(filename);
	enable_raw_output(outfile);

	print outfile, x509_get_certificate_string(cert, T);

	close(outfile);
	}

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=5
	{
	set_session(c);
	c$ssl$client_random = bytestring_to_hexstr(client_random);

	local ciphers_str = "";
	for (i in ciphers)
		{
			ciphers_str += cipher_desc[ciphers[i]];
			if ( i != |ciphers|-1)
				{
					ciphers_str += ",";
				}
		}
	c$ssl$client_cipher_suites = ciphers_str;
	}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=5
	{
	set_session(c);
	c$ssl$server_random = bytestring_to_hexstr(server_random);
	}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string) &priority=5
	{
	set_session(c);
	c$ssl$server_dh_p = bytestring_to_hexstr(p);
	c$ssl$server_dh_q = bytestring_to_hexstr(q);
	c$ssl$server_dh_Ys = bytestring_to_hexstr(Ys);
	}

event ssl_ecdh_server_params(c: connection, curve: count, point: string) &priority=5
	{
	set_session(c);
	c$ssl$server_ecdh_point = bytestring_to_hexstr(point);
	}

event ssl_server_signature(c: connection, signed_params: string) &priority=5
	{
	set_session(c);
	c$ssl$server_signature = bytestring_to_hexstr(signed_params);
	}

event ssl_rsa_client_pms(c: connection, pms: string) &priority=5
	{
	set_session(c);
	c$ssl$client_rsa_pms = bytestring_to_hexstr(pms);
	}

event ssl_dh_client_params(c: connection, Yc: string) &priority=5
	{
	set_session(c);
	c$ssl$client_dh_Yc = bytestring_to_hexstr(Yc);
	}

event ssl_ecdh_client_params(c: connection, point: string) &priority=5
	{
	set_session(c);
	c$ssl$client_ecdh_point = bytestring_to_hexstr(point);
	}

