##! The storage framework provides a way to store long-term
##! data to disk.

@load base/bif/storage.bif

module Storage;

export {
	global open_backend: function(btype: Storage::Backend, config: any, val_type: any): opaque of Storage::BackendHandle;
	global close_backend: function(backend: opaque of Storage::BackendHandle): bool;
	global store: function(backend: opaque of Storage::BackendHandle, key: any, value: any, overwrite: bool): bool;
	global retrieve: function(backend: opaque of Storage::BackendHandle, key: any): any;
	global erase: function(backend: opaque of Storage::BackendHandle, key: any): bool;
}

function open_backend(btype: Storage::Backend, config: any, val_type: any): opaque of Storage::BackendHandle
{
	return Storage::__open_backend(btype, config, val_type);
}

function close_backend(backend: opaque of Storage::BackendHandle): bool
{
	return Storage::__close_backend(backend);
}

function store(backend: opaque of Storage::BackendHandle, key: any, value: any, overwrite: bool): bool
{
	return Storage::__store(backend, key, value, overwrite);
}

function retrieve(backend: opaque of Storage::BackendHandle, key: any): any
{
	return Storage::__retrieve(backend, key);
}

function erase(backend: opaque of Storage::BackendHandle, key: any): bool
{
	return Storage::__erase(backend, key);
}
