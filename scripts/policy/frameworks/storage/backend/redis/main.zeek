##! Redis storage backend support

@load base/frameworks/storage/main

module Storage::Backend::Redis;

export {
	## Default value for connection attempt timeouts. This can be overridden
	## per-connection with the ``connect_timeout`` backend option.
	const default_connect_timeout: interval = 5 secs &redef;

	## Default value for operation timeouts. This can be overridden per-connection
	## with the ``operation_timeout`` backend option.
	const default_operation_timeout: interval = 5 secs &redef;

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

		## Timeout for connection attempts to the backend. Connection attempts
		## that exceed this time will return
		## :zeek:see:`Storage::CONNECTION_FAILED`.
		connect_timeout: interval &default=default_connect_timeout;

		## Timeout for operation requests sent to the backend. Operations that
		## exceed this time will return :zeek:see:`Storage::TIMEOUT`.
		operation_timeout: interval &default=default_operation_timeout;

		## A username to use for authentication the server is protected by an ACL.
		username: string &optional;

		## A username to use for authentication the server is protected by an ACL
		## or by a simple password.
		password: string &optional;
	};
}

redef record Storage::BackendOptions += {
	redis: Storage::Backend::Redis::Options &optional;
};
