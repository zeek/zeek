##! The storage framework provides a way to store long-term data to disk.

@load base/bif/storage.bif

module Storage;

export {
    ## Base record for backend options. Backend plugins can redef this record to add
    ## relevant fields to it.
    type BackendOptions: record {};

	## Record for passing arguments to :zeek:see:`Storage::Async::put` and
	## :zeek:see:`Storage::Sync::put`.
	type PutArgs: record {
		# The key to store the value under.
		key: any;

		# The value to store associated with the key.
		value: any;

		# Indicates whether this value should overwrite an existing entry for the
		# key.
		overwrite: bool &default=T;

		# An interval of time until the entry is automatically removed from the
		# backend.
		expire_time: interval &default=0sec;
	};
}
