##! The storage framework provides a way to store long-term data to disk.

@load base/bif/storage.bif

module Storage;

export {
	## Record for passing arguments to :zeek:see:`Storage::put`.
	type PutArgs: record {
		backend: opaque of Storage::BackendHandle;

		# The script-level type of keys stored in the backend. Used for
		# validation of keys passed to other framework methods.
		key: any;

		# The script-level type of keys stored in the backend. Used for
		# validation of values passed to :zeek:see:`Storage::put` as
		# well for type conversions for return values from
		# :zeek:see:`Storage::get`.
		value: any;

		# Indicates whether this value should overwrite an existing entry
		# for the key.
		overwrite: bool &default=F;

		# An interval of time until the entry is automatically removed from the
		# backend.
		expire_time: interval &default=0sec;

		# Indicates whether this operation should happen
		# asynchronously. If this is true, the call to put must happen
		# as part of a when statement. This flag is overridden when
		# reading pcaps, since time won't move forward the same as when
		# caputring live traffic.
		async_mode: bool &default=T;
	};

	## Opens a new backend connection based on a configuration object.
	##
	## btype: A tag indicating what type of backend should be opened.
	##
	## config: A record containing the configuration for the connection.
	##
	## key_type: The Val type of the key being stored.
	##
	## val_type: The Val type of the key being stored.
	##
	## async_mode: Indicates whether this operation should happen
	##             asynchronously. If this is T, the call must happen as
	##             part of a :zeek:see:`when` statement.
	##
	## Returns: A handle to the new backend connection, or null if the
	##          connection failed.
	global open_backend: function(btype: Storage::Backend, config: any, key_type: any,
	                              val_type: any, async_mode: bool &default=F): opaque of Storage::BackendHandle;

	## Closes an existing backend connection.
	##
	## backend: A handle to a backend connection.
	##
	## async_mode: Indicates whether this operation should happen
	##             asynchronously. If this is T, the call must happen as
	##             part of a :zeek:see:`when` statement.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global close_backend: function(backend: opaque of Storage::BackendHandle, async_mode: bool &default=F): bool;

	## Inserts a new entry into a backend.
	##
	## Returns: A boolean indicating success or failure of the
	##          operation. Type comparison failures against the types passed
	##          to :zeek:see:`Storage::open_backend` for the backend will
	##          cause false to be returned.
	global put: function(args: Storage::PutArgs): bool;

	## Gets an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to look up.
	##
	## async_mode: Indicates whether this operation should happen
	##             asynchronously. If this is T, the call must happen as
	##             part of a :zeek:see:`when` statement.
	##
	## Returns: A boolean indicating success or failure of the operation.
	##          Type comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause
	##          false to be returned.
	global get: function(backend: opaque of Storage::BackendHandle, key: any,
			     async_mode: bool &default=T): val_result;

	## Erases an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to erase.
	##
	## async_mode: Indicates whether this operation should happen
	##             asynchronously. If this is T, the call must happen as
	##             part of a :zeek:see:`when` statement.
	##
	## Returns: A boolean indicating success or failure of the operation.
	##          Type comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause
	##          false to be returned.
	global erase: function(backend: opaque of Storage::BackendHandle, key: any,
			       async_mode: bool &default=T): bool;
}

function open_backend(btype: Storage::Backend, config: any, key_type: any, val_type: any, async_mode: bool &default=F): opaque of Storage::BackendHandle
{
	return Storage::__open_backend(btype, config, key_type, val_type, async_mode);
}

function close_backend(backend: opaque of Storage::BackendHandle, async_mode: bool &default=F): bool
{
	return Storage::__close_backend(backend, async_mode);
}

function put(args: Storage::PutArgs): bool
{
	return Storage::__put(args$backend, args$key, args$value, args$overwrite, args$expire_time, args$async_mode);
}

function get(backend: opaque of Storage::BackendHandle, key: any, async_mode: bool &default=T): val_result
{
	return Storage::__get(backend, key, async_mode);
}

function erase(backend: opaque of Storage::BackendHandle, key: any, async_mode: bool &default=T): bool
{
	return Storage::__erase(backend, key, async_mode);
}
