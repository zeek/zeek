##! This script allows for the decryption of certain TLS 1.2 connections, if the user is in possession
##! of the private key material for the session. Key material can either be provided via a file (useful
##! for processing trace files) or via sending events via Broker (for live decoding).
##!
##! Please note that this feature is experimental and can change without guarantees to our typical
##! deprecation timeline. Please also note that currently only TLS 1.2 connections that use the
##! TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 cipher suite are supported.

@load base/frameworks/input
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl

module SSL;

# Do not disable analyzers after detection - otherwise we will not receive
# encrypted packets.
redef SSL::disable_analyzer_after_detection = F;

export {
	## This can be set to a file that contains the session secrets for decryption, when parsing a pcap file.
	## Please note that, when using this feature, you probably want to pause processing of data till this
	## file has been read.
	const keylog_file = getenv("ZEEK_TLS_KEYLOG_FILE") &redef;

	## Secrets expire after this time of not being used.
	const secret_expiration = 5 mins &redef;

	## This event can be triggered, e.g., via Broker to add known keys to the TLS key database.
	##
	## client_random: client random for which the key is set
	##
	## keys: key material
	global add_keys: event(client_random: string, keys: string);

	## This event can be triggered, e.g., via Broker to add known secrets to the TLS secret database.
	##
	## client_random: client random for which the secret is set
	##
	## secrets: derived TLS secrets material
	global add_secret: event(client_random: string, secrets: string);
}

@if ( keylog_file == "" )
# If a keylog file was given via an environment variable, let's disable secret expiration - that does not
# make sense for pcaps.
global secrets: table[string] of string = {} &redef;
global keys: table[string] of string = {} &redef;
@else
global secrets: table[string] of string = {} &read_expire=secret_expiration &redef;
global keys: table[string] of string = {} &read_expire=secret_expiration &redef;
@endif


redef record SSL::Info += {
	# Decryption uses client_random as identifier
	client_random: string &optional;
};

type SecretsIdx: record {
	client_random: string;
};

type SecretsVal: record {
	secret: string;
};

const tls_decrypt_stream_name = "tls-keylog-file";

event zeek_init()
	{
	# listen for secrets
	Broker::subscribe("/zeek/tls/decryption");

	if ( keylog_file != "" )
		{
		Input::add_table([$name=tls_decrypt_stream_name, $source=keylog_file, $destination=secrets, $idx=SecretsIdx, $val=SecretsVal, $want_record=F]);
		Input::remove(tls_decrypt_stream_name);
		}
	}

event SSL::add_keys(client_random: string, val: string)
	{
	SSL::keys[client_random] = val;
	}

event SSL::add_secret(client_random: string, val: string)
	{
	SSL::secrets[client_random] = val;
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
	{
	c$ssl$client_random = client_random;

	if ( client_random in keys )
		set_keys(c, keys[client_random]);
	else if ( client_random in secrets )
		set_secret(c, secrets[client_random]);
	}

event ssl_change_cipher_spec(c: connection, is_client: bool)
	{
	if ( c$ssl?$client_random )
		{
		if ( c$ssl$client_random in keys )
			set_keys(c, keys[c$ssl$client_random]);
		else if ( c$ssl$client_random in secrets )
			set_secret(c, secrets[c$ssl$client_random]);
		}
	}
