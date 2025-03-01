##! Asynchronous operation methods for the storage framework. These methods must
##! be called as part of a :zeek:see:`when` statement. An error will be returned
##! otherwise.

@load ./main

module Storage::Async;

export {
	## Opens a new backend connection based on a configuration object asynchronously.
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
	##           validation of values passed to :zeek:see:`Storage::Async::put` as
	##           well as for type conversions for return values from
	##           :zeek:see:`Storage::Async::get`.
	##
	## Returns: A handle to the new backend connection, or ``F`` if the connection
	##          failed.
	global open_backend: function(btype: Storage::Backend, options: any, key_type: any,
	                              val_type: any): opaque of Storage::BackendHandle;

	## Closes an existing backend connection asynchronously.
	##
	## backend: A handle to a backend connection.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global close_backend: function(backend: opaque of Storage::BackendHandle): bool;

	## Inserts a new entry into a backend asynchronously.
	##
	## backend: A handle to a backend connection.
	##
	## args: A :zeek:see:`Storage::PutArgs` record containing the arguments for the
	##       operation.
	##
	## Returns: A boolean indicating success or failure of the operation. Type
	##          comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause ``F`` to
	##          be returned.
	global put: function(backend: opaque of Storage::BackendHandle, args: Storage::PutArgs): bool;

	## Gets an entry from the backend asynchronously.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to look up.
	##
	## Returns: A boolean indicating success or failure of the operation.  Type
	##          comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause ``F`` to
	##          be returned. The caller should check the validity of the value before
	##          attempting to use it. If the value is unset, an error string may be
	##          available to describe the failure.
	global get: function(backend: opaque of Storage::BackendHandle, key: any): val_result;

	## Erases an entry from the backend asynchronously.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to erase.
	##
	## Returns: A boolean indicating success or failure of the operation.  Type
	##          comparison failures against the types passed to
	##          :zeek:see:`Storage::open_backend` for the backend will cause ``F`` to
	##          be returned.
	global erase: function(backend: opaque of Storage::BackendHandle, key: any): bool;
}

function open_backend(btype: Storage::Backend, options: any, key_type: any, val_type: any): opaque of Storage::BackendHandle
{
	return Storage::Async::__open_backend(btype, options, key_type, val_type);
}

function close_backend(backend: opaque of Storage::BackendHandle): bool
{
	return Storage::Async::__close_backend(backend);
}

function put(backend: opaque of Storage::BackendHandle, args: Storage::PutArgs): bool
{
	return Storage::Async::__put(backend, args$key, args$value, args$overwrite, args$expire_time);
}

function get(backend: opaque of Storage::BackendHandle, key: any): val_result
{
	return Storage::Async::__get(backend, key);
}

function erase(backend: opaque of Storage::BackendHandle, key: any): bool
{
	return Storage::Async::__erase(backend, key);
}
