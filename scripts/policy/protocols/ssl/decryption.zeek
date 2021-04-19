#! Decrypt SSL/TLS payloads

@load base/frameworks/input
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl

module SSL;

# Local
const input_stream_name = "input-tls-keylog-file";

type Idx: record {
	client_random: string;
};

type Val: record {
	secret: string;
};

global randoms: table[string] of string = {};

export {
	redef record Info += {
		# decryption uses client_random as identifier
		client_random: string &log &optional;
	};

	const keylog_file = getenv("ZEEK_TLS_KEYLOG_FILE") &redef;

	global secrets: table[string] of string = {} &redef;
	global keys: table[string] of string = {} &redef;

	event SSL::add_keys(client_random: string, val: string)
	{
		SSL::keys[client_random] = val;
	}

	event SSL::add_secret(client_random: string, val: string)
	{
		SSL::secrets[client_random] = val;
	}
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
	{
	c$ssl$client_random = client_random;

	if ( client_random in keys )
		{
		set_keys(c, keys[client_random]);
		}
	else if ( client_random in secrets )
		{
		set_secret(c, secrets[client_random]);
		}
	}

event ssl_encrypted_data(c: connection, is_orig: bool, record_version: count, content_type: count, length: count, payload: string)
	{
	if ( c$ssl?$client_random )
		{
		if ( c$ssl$client_random in keys )
			{
			set_keys(c, keys[c$ssl$client_random]);
			}
		else if ( c$ssl$client_random in secrets )
			{
			set_secret(c, secrets[c$ssl$client_random]);
			}
		else
			{
			# FIXME: should this be moved to reporter.log or removed completely?
			#print "No suitable key or secret found for random:", randoms[c$uid];
			}
		}
	}

event SSL::tls_input_done()
	{
	continue_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name == input_stream_name )
	{
		event SSL::tls_input_done();
	}
}

event zeek_init()
	{
	# listen for secrets
	Broker::subscribe("/zeek/tls/decryption");

	# FIXME: is such a functionality helpful?
	# ingest keylog file if the environment is set
	if ( keylog_file != "" )
		{
		suspend_processing();

		Input::add_table([$name=input_stream_name, $source=keylog_file, $destination=secrets, $idx=Idx, $val=Val, $want_record=F]);
		Input::remove(input_stream_name);
		}
}
