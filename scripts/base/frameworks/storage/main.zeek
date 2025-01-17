##! The storage framework provides a way to store long-term data to disk.

@load base/bif/storage.bif

module Storage;

export {
	## Record for passing arguments to :zeek:see:`Storage::put`.
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

		# Indicates whether this operation should happen asynchronously. If this
		# is true, the call to put must happen as part of a :zeek:see:`when`
		# statement. This flag is overridden and set to F when reading pcaps,
		# since time won't move forward the same as when caputring live traffic.
		async_mode: bool &default=T;
	};

	## Opens a new backend connection based on a configuration object.
	##
	## btype: A tag indicating what type of backend should be opened. These are
	##        defined by the backend plugins loaded.
	##
	## options: A record containing the configuration for the connection.
	##
	## key_type: The script-level type of keys stored in the backend. Used for
	##           validation of keys passed to other framework methods.
	##
	## val_type: The script-level type of keys stored in the backend. Used for
	##           validation of values passed to :zeek:see:`Storage::put` as well as
	##           for type conversions for return values from :zeek:see:`Storage::get`.
	##
	## async_mode: Indicates whether this operation should happen asynchronously. If
	##             this is T, the call must happen as part of a :zeek:see:`when`
	##             statement. This flag is overridden and set to F when reading pcaps,
	##             since time won't move forward the same as when caputring live
	##             traffic.
	##
	## Returns: A handle to the new backend connection, or ``F`` if the connection
	##          failed.
	global open_backend: function(btype: Storage::Backend, options: any, key_type: any,
	                              val_type: any, async_mode: bool &default=F): opaque of Storage::BackendHandle;

	## Closes an existing backend connection.
	##
	## backend: A handle to a backend connection.
	##
	## async_mode: Indicates whether this operation should happen asynchronously. If
	##             this is T, the call must happen as part of a :zeek:see:`when`
	##             statement. This flag is overridden and set to F when reading pcaps,
	##             since time won't move forward the same as when caputring live
	##             traffic.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global close_backend: function(backend: opaque of Storage::BackendHandle, async_mode: bool &default=F): bool;

	## Inserts a new entry into a backend.
	##
	##
	## backend: A handle to a backend connection.
	##
	## args: A :zeek:see:`Storage::PutArgs` record containing the arguments for the
	## operation.
	##
	## Returns: A boolean indicating success or failure of the operation. Type
	##          comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause ``F`` to
	##          be returned.
	global put: function(backend: opaque of Storage::BackendHandle, args: Storage::PutArgs): bool;

	## Gets an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to look up.
	##
	## async_mode: Indicates whether this operation should happen asynchronously. If
	##             this is T, the call must happen as part of a :zeek:see:`when`
	##             statement. This flag is overridden and set to F when reading pcaps,
	##             since time won't move forward the same as when caputring live
	##             traffic.
	##
	## Returns: A boolean indicating success or failure of the operation.  Type
	##          comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause ``F`` to
	##          be returned.
	global get: function(backend: opaque of Storage::BackendHandle, key: any,
			     async_mode: bool &default=T): any;

	## Erases an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to erase.
	##
	## async_mode: Indicates whether this operation should happen asynchronously. If
	##             this is T, the call must happen as part of a :zeek:see:`when`
	##             statement. This flag is overridden and set to F when reading pcaps,
	##             since time won't move forward the same as when caputring live
	##             traffic.
	##
	## Returns: A boolean indicating success or failure of the operation.  Type
	##          comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause ``F`` to
	##          be returned.
	global erase: function(backend: opaque of Storage::BackendHandle, key: any,
			       async_mode: bool &default=T): bool;
}

function open_backend(btype: Storage::Backend, options: any, key_type: any, val_type: any, async_mode: bool &default=F): opaque of Storage::BackendHandle
{
	return Storage::__open_backend(btype, options, key_type, val_type, async_mode);
}

function close_backend(backend: opaque of Storage::BackendHandle, async_mode: bool &default=F): bool
{
	return Storage::__close_backend(backend, async_mode);
}

function put(backend: opaque of Storage::BackendHandle, args: Storage::PutArgs): bool
{
	return Storage::__put(backend, args$key, args$value, args$overwrite, args$expire_time, args$async_mode);
}

function get(backend: opaque of Storage::BackendHandle, key: any, async_mode: bool &default=T): any
{
	return Storage::__get(backend, key, async_mode);
}

function erase(backend: opaque of Storage::BackendHandle, key: any, async_mode: bool &default=T): bool
{
	return Storage::__erase(backend, key, async_mode);
}
