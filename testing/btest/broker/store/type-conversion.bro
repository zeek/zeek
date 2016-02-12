# @TEST-EXEC: btest-bg-run master "bro -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out

type R1: record {
    s: string;
};

type R2: record {
    c: count;
    r1: R1;
};

event bro_init()
	{
	### Print every broker data type
	print Broker::data_type(Broker::data(T));
	print Broker::data_type(Broker::data(+1));
	print Broker::data_type(Broker::data(1));
	print Broker::data_type(Broker::data(1.1));
	print Broker::data_type(Broker::data("1 (how creative)"));
	print Broker::data_type(Broker::data(1.1.1.1));
	print Broker::data_type(Broker::data(1.1.1.1/1));
	print Broker::data_type(Broker::data(1/udp));
	print Broker::data_type(Broker::data(double_to_time(1)));
	print Broker::data_type(Broker::data(1sec));
	print Broker::data_type(Broker::data(Broker::BOOL));
	print Broker::data_type(Broker::data(set("one", "two", "three")));
	print Broker::data_type(Broker::data(table(["one"] = 1, ["two"] = 2, ["three"] = 3)));
	print Broker::data_type(Broker::data(vector("zero", "one", "two")));
	print Broker::data_type(Broker::data(R1($s="abc")));
	print Broker::data_type(Broker::data(R2($c=123, $r1=R1($s="xyz"))));

	print "***************************";

        ### Convert a Bro value to a broker value, then print the result

	print (Broker::data(T) as bool);
	print (Broker::data(F) as bool);
	print (Broker::data(+1) as int);
	print (Broker::data(+0) as int);
	print (Broker::data(-1) as int);
	print (Broker::data(1) as count);
	print (Broker::data(0) as count);
	print (Broker::data(1.1) as double);
	print (Broker::data(-11.1) as double);
	print (Broker::data("hello") as string);
	print (Broker::data(1.2.3.4) as addr);
	print (Broker::data(192.168.1.1/16) as subnet);
	print (Broker::data(22/tcp) as port);
	print (Broker::data(double_to_time(42)) as time);
	print (Broker::data(3min) as interval);
	print (Broker::data(Broker::BOOL) as Broker::DataType);
	print (Broker::data(set("one", "two", "three")) as set[string]);
	print (Broker::data(table(["one"] = 1, ["two"] = 2, ["three"] = 3)) as table[string] of count);
	print (Broker::data(vector("zero", "one", "two")) as vector of string);
	print (Broker::data(R1($s="abc")) as R1);
	print (Broker::data(R2($c=123, $r1=R1($s="xyz"))) as R2);

	local h1 = sha256_hash_init();
	sha256_hash_update(h1, "abc");
	local h2 = (Broker::data(h1) as opaque of sha256);
	local s1 = sha256_hash_finish(h1);
	local s2 = sha256_hash_finish(h2);
	print "opaque of sha256", s1 == s2;
	}
