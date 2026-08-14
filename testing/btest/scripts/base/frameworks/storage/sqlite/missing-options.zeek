# @TEST-DOC: Opening a backend with default options reports an error instead of crashing
# @TEST-EXEC: zeek -b %INPUT

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

event zeek_init() {
	local opts: Storage::BackendOptions;
	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string);
	assert open_res$code == Storage::INITIALIZATION_FAILED;
}
