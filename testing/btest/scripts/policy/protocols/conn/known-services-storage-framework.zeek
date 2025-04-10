# A test case for when more than a single service is detected for a given
# (addr, port) pair. This uses the storage framework to store the services.

# @TEST-EXEC: zeek -b -C -r $TRACES/ssl-and-ssh-using-sslh.trace %INPUT "Known::service_tracking = ALL_HOSTS"
# @TEST-EXEC: btest-diff known_services.log

@load base/protocols/ssh
@load base/protocols/ssl
@load protocols/conn/known-services
@load policy/frameworks/storage/backend/sqlite

redef Known::use_service_store = T;

redef Known::use_storage_framework = T;
redef Known::service_store_backend_type = Storage::STORAGE_BACKEND_SQLITE;
redef Known::service_store_backend_options = [ $sqlite = [
    $database_path="test.sqlite", $table_name=Known::service_store_prefix ]];
