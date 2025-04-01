##! The storage framework provides a way to store long-term data to disk.

module Storage;

export {
	## Base record for backend options that can be passed to
	## :zeek:see:`Storage::Async::open_backend` and
	## :zeek:see:`Storage::Sync::open_backend`. Backend plugins can redef this record
	## to add relevant fields to it.
	type BackendOptions: record {
		## The serializer used for converting Zeek data.
		serializer: Storage::Serializer &default=Storage::STORAGE_SERIALIZER_JSON;

		## Indicates whether this node in a cluster handles expiration for a
		## backend that only supports non-native expiration. Having a single node
		## handle expiration avoids race conditions where multiple nodes may be
		## attempting to expire elements at the same time. In a cluster
		## environment this defaults to ``F``, and one node that opens the backend
		## will need to set it to ``T`` for expiration to function. This value is
		## ignored in standalone/non-cluster environments.
		expiration_master : bool &default=F;
	};

	## Record for passing arguments to :zeek:see:`Storage::Async::put` and
	## :zeek:see:`Storage::Sync::put`.
	type PutArgs: record {
		## The key to store the value under.
		key: any;

		## The value to store associated with the key.
		value: any;

		## Indicates whether this value should overwrite an existing entry for the
		## key.
		overwrite: bool &default=T;

		## An interval of time until the entry is automatically removed from the
		## backend.
		expire_time: interval &default=0sec;
	};

	## This is the name of a node that should handle expiration master duties for all
	## opened backends. This can be overridden by setting the
	const global_expiration_master: string &redef;
}
