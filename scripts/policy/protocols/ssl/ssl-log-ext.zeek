##! This file adds a lot of additional information to the SSL log
##! It is not loaded by default since the information significantly expands
##! the log and is probably not interesting for a majority of people.

@load base/protocols/ssl

module SSL;

redef record SSL::Info += {
	## Numeric version of the server in the server hello
	server_version: count &log &optional;
	## Numeric version of the client in the client hello
	client_version: count &log &optional;
	## Ciphers that were offered by the client for the connection
	client_ciphers: vector of count  &log &optional;
	## SSL Client extensions
	ssl_client_exts: vector of count &log &optional;
	## SSL server extensions
	ssl_server_exts: vector of count &log &optional;
	## Suggested ticket lifetime sent in the session ticket handshake
	## by the server.
	ticket_lifetime_hint: count &log &optional;
	## The diffie helman parameter size, when using DH.
	dh_param_size: count &log &optional;
	## supported elliptic curve point formats
	point_formats: vector of count  &log &optional;
	## The curves supported by the client.
	client_curves: vector of count  &log &optional;
	## Application layer protocol negotiation extension sent by the client.
	orig_alpn: vector of string &log &optional;
	## TLS 1.3 supported versions
	client_supported_versions: vector of count &log &optional;
	## TLS 1.3 supported versions
	server_supported_version: count &log &optional;
	## TLS 1.3 Pre-shared key exchange modes
	psk_key_exchange_modes: vector of count &log &optional;
	## Key share groups from client hello
	client_key_share_groups: vector of count &log &optional;
	## Selected key share group from server hello
	server_key_share_group: count &log &optional;
	## Client supported compression methods
	client_comp_methods: vector of count &log &optional;
	## Server chosen compression method
	comp_method: count &optional;
	## Client supported signature algorithms
	sigalgs: vector of count &log &optional;
	## Client supported hash algorithms
	hashalgs: vector of count &log &optional;
};

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
	{
	set_session(c);

	c$ssl$client_ciphers = ciphers;
	c$ssl$client_version = version;
	c$ssl$client_comp_methods = comp_methods;
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
	{
	set_session(c);

	c$ssl$server_version = version;
	c$ssl$comp_method = comp_method;
	}

event ssl_session_ticket_handshake(c: connection, ticket_lifetime_hint: count, ticket: string)
	{
	set_session(c);

	c$ssl$ticket_lifetime_hint = ticket_lifetime_hint;
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	set_session(c);

	if ( is_client )
		{
		if ( ! c$ssl?$ssl_client_exts )
			c$ssl$ssl_client_exts = vector();
		c$ssl$ssl_client_exts[|c$ssl$ssl_client_exts|] = code;
		}
	else
		{
		if ( ! c$ssl?$ssl_server_exts )
			c$ssl$ssl_server_exts = vector();
		c$ssl$ssl_server_exts[|c$ssl$ssl_server_exts|] = code;
		}
	}

event ssl_extension_ec_point_formats(c: connection, is_client: bool, point_formats: index_vec)
	{
	if ( ! is_client )
		return;

	set_session(c);

	c$ssl$point_formats = point_formats;
	}

event ssl_extension_elliptic_curves(c: connection, is_client: bool, curves: index_vec)
	{
	if ( ! is_client )
		return;

	set_session(c);

	c$ssl$client_curves = curves;
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, names: string_vec)
	{
	set_session(c);

	if ( is_client )
		c$ssl$orig_alpn = names;
	}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string)
	{
	set_session(c);

	local key_length = |Ys| * 8; # key length in bits
	c$ssl$dh_param_size = key_length;
	}

event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec)
	{
	set_session(c);

	if ( is_client )
		c$ssl$client_supported_versions = versions;
	else
		c$ssl$server_supported_version = versions[0];
	}

event ssl_extension_psk_key_exchange_modes(c: connection, is_client: bool, modes: index_vec)
	{
	if ( ! is_client )
		return;

	set_session(c);

	c$ssl$psk_key_exchange_modes = modes;
	}

event ssl_extension_key_share(c: connection, is_client: bool, curves: index_vec)
	{
	set_session(c);

	if ( is_client )
		c$ssl$client_key_share_groups = curves;
	else
		c$ssl$server_key_share_group = curves[0];
	}

event ssl_extension_signature_algorithm(c: connection, is_client: bool, signature_algorithms: signature_and_hashalgorithm_vec)
	{
	if ( ! is_client )
		return;

	set_session(c);

	local sigalgs: index_vec = vector();
	local hashalgs: index_vec = vector();

	for ( i in signature_algorithms )
		{
		local rec = signature_algorithms[i];
		sigalgs[|sigalgs|] = rec$SignatureAlgorithm;
		hashalgs[|hashalgs|] = rec$HashAlgorithm;
		}

	c$ssl$sigalgs = sigalgs;
	c$ssl$hashalgs = hashalgs;
	}
