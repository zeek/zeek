##! The storage framework provides a way to store long-term data to disk.

@load base/bif/storage.bif

module Storage;

export {
	## Opens a new backend connection based on a configuration object.
	##
	## btype: A tag indicating what type of backend should be opened.
	##
	## options: A record containing the configuration for the connection.
	##
	## Returns: A handle to the new backend connection, or null if the
	##          connection failed.
	global open_backend: function(btype: Storage::Backend, options: any): opaque of Storage::BackendHandle;

	## Closes an existing backend connection.
	##
	## backend: A handle to a backend connection.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global close_backend: function(backend: opaque of Storage::BackendHandle): bool;

	## Inserts a new entry into a backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: A key value.
	##
	## value: A corresponding value.
	##
	## overwrite: A flag indicating whether this value should overwrite an
	##            existing entry for the key.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global put: function(backend: opaque of Storage::BackendHandle, key: any, value: any, overwrite: bool): bool;

	## Gets an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to look up.
	##
	## val_type: The type of the value to return.
	##
	## Returns: A boolean indicating success or failure of the
	##          operation. Type conversion failures for the value will
	##          return false.
	global get: function(backend: opaque of Storage::BackendHandle, key: any, val_type: any): any;

	## Erases an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to erase.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global erase: function(backend: opaque of Storage::BackendHandle, key: any): bool;
}

function open_backend(btype: Storage::Backend, options: any): opaque of Storage::BackendHandle
{
	return Storage::__open_backend(btype, options);
}

function close_backend(backend: opaque of Storage::BackendHandle): bool
{
	return Storage::__close_backend(backend);
}

function put(backend: opaque of Storage::BackendHandle, key: any, value: any, overwrite: bool): bool
{
	return Storage::__put(backend, key, value, overwrite);
}

function get(backend: opaque of Storage::BackendHandle, key: any, val_type: any): any
{
	return Storage::__get(backend, key, val_type);
}

function erase(backend: opaque of Storage::BackendHandle, key: any): bool
{
	return Storage::__erase(backend, key);
}
