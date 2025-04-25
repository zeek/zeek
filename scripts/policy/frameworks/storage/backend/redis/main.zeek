##! Redis storage backend support

@load base/frameworks/storage/main

module Storage::Backend::Redis;

export {
	## Options record for the built-in Redis backend.
	type Options: record {
		# Address or hostname of the server.
		server_host: string &optional;

		# Port for the server.
		server_port: port &default=6379/tcp;

		# Server unix socket file. This can be used instead of the address and
		# port above to connect to a local server. In order to use this, the
		# ``server_host`` field must be unset.
		server_unix_socket: string &optional;

		# Prefix used in keys stored to differentiate varying types of data on the
		# same server. Defaults to an empty string, but preferably should be set
		# to a unique value per Redis backend opened.
		key_prefix: string &default="";
	};
}

redef record Storage::BackendOptions += {
	redis: Storage::Backend::Redis::Options &optional;
};
