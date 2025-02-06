##! Redis storage backend support

@load base/frameworks/storage/main

module Storage::Backend::Redis;

export {
	## Options record for the built-in Redis backend.
	type Options: record {
		# Address or hostname of the server
		server_host: string &optional;

		# Port for the server
		server_port: port &default=6379/tcp;

		# Server unix socket file. This can be used instead of the
		# address and port above to connect to a local server.
		server_unix_socket: string &optional;

		# Prefix used in key values stored to differentiate varying
		# types of data on the same server. Defaults to an empty string,
		# but preferably should be set to a unique value per Redis
		# backend opened.
		key_prefix: string &default="";

		# Redis only supports sync and async separately. You cannot do
		# both with the same connection. If this flag is true, the
		# connection will be async and will only allow commands via
		# ``when`` commands. You will still need to set the
		# ``async_mode`` flags of the put, get, and erase methods to
		# match this flag. This flag is overridden when reading pcaps
		# and the backend will be forced into synchronous mode, since
		# time won't move forward the same as when capturing live
		# traffic.
		async_mode: bool &default=T;
	};

	redef record Storage::BackendOptions += {
		redis: Options &optional;
	};
}
