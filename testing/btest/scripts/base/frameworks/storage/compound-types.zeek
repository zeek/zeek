# @TEST-DOC: Test operations using more complicated types
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

type Color: enum {
	Red = 10,
	White = 20,
	Blue = 30
};

type Rec: record
{
	hello: string;
	t: bool;
	f: bool;
	n: count &optional;
	m: count &optional;  # not in input
	def: count &default = 123;
	i: int;
	pi: double;
	a: string_vec;
	c1: Color;
	p: port;
	ti: time;
	it: interval;
	ad: addr;
	s: subnet;
	re: pattern;
	su: subnet_set;
};

type tbl: table[count] of string;

event zeek_init() {
	# Create a database file in the .tmp directory with a 'testing' table
	local opts : Storage::BackendOptions;
	opts$sqlite = [$database_path = "types_test.sqlite", $table_name = "types_testing"];

	local key : Rec;
	key$hello = "hello";
	key$t = T;
	key$f = F;
	key$n = 1234;
	key$m = 5678;
	key$i = -2345;
	key$pi = 345.0;
	key$a = ["a","b","c"];
	key$c1 = Red;
	key$p = 1234/tcp;
	key$ti = current_time();
	key$it = 15sec;
	key$ad = 1.2.3.4;
	key$s = 255.255.255.0/24;
	key$re = /.*/;
	key$su = [255.255.255.0/24];

	local value : tbl;
	value[1] = "a";
	value[2] = "b";
	value[3] = "c";

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, Rec, tbl);
	print "open result", open_res;
	local b = open_res$value;

	local res = Storage::Sync::put(b, [$key=key, $value=value]);
	print "put result", res;

	local res2 = Storage::Sync::get(b, key);
	print "get result", res2;
}
