# @TEST-DOC: Tests basic Redis storage backend functions in async mode

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# Generate a redis.conf file with the port defined above, but without the /tcp at the end of
# it. This also sets some paths in the conf to the testing directory.
# @TEST-EXEC: cat $FILES/redis.conf | sed "s|%REDIS_PORT%|${REDIS_PORT%/tcp}|g" | sed "s|%RUN_PATH%|$(pwd)|g" > ./redis.conf
# @TEST-EXEC: btest-bg-run redis redis-server ../redis.conf
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage
@load policy/frameworks/storage/backend/redis

redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into open_backend()
type str: string;

event zeek_init() {
	local opts : Storage::Backend::Redis::Options;
	opts$server_host = "127.0.0.1";
	opts$server_port = to_port(getenv("REDIS_PORT"));
	opts$key_prefix = "testing";
	opts$async_mode = T;

	local key = "key1234";
	local value = "value5678";

	local b = Storage::open_backend(Storage::REDIS, opts, str, str);

	when [b, key, value] ( local res = Storage::put(b, [$key=key, $value=value]) ) {
		print "put result", res;

		when [b, key, value] ( local res2 = Storage::get(b, key) ) {
			print "get result", res2;
			print "get result same as inserted", value == (res2 as string);

			Storage::close_backend(b);

			terminate();
		}
		timeout 5 sec {
			print "get requeest timed out";
			terminate();
		}
	}
	timeout 5 sec {
		print "put request timed out";
		terminate();
	}
}
