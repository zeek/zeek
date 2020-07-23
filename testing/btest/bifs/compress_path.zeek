#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function CHECK(result: string, expect: string)
	{
	print result == expect, result, expect;
	}

event zeek_init()
	{
	CHECK(compress_path("./../foo"), "../foo");
	CHECK(compress_path("././../foo"), "../foo");
	CHECK(compress_path("/1/2/3"), "/1/2/3");
	CHECK(compress_path("/1/./2/3"), "/1/2/3");
	CHECK(compress_path("/1/2/../3"), "/1/3");
	CHECK(compress_path("1/2/3/"), "1/2/3");
	CHECK(compress_path("1/2//3///"), "1/2/3");
	CHECK(compress_path("~/zeek/testing"), "~/zeek/testing");
	CHECK(compress_path("~jon/zeek/testing"), "~jon/zeek/testing");
	CHECK(compress_path("~jon/./zeek/testing"), "~jon/zeek/testing");
	CHECK(compress_path("~/zeek/testing/../././."), "~/zeek");
	CHECK(compress_path("./zeek"), "./zeek");
	CHECK(compress_path("../zeek"), "../zeek");
	CHECK(compress_path("../zeek/testing/.."), "../zeek");
	CHECK(compress_path("./zeek/.."), ".");
	CHECK(compress_path("./zeek/../.."), "..");
	CHECK(compress_path("./zeek/../../.."), "../..");
	CHECK(compress_path("./.."), "..");
	CHECK(compress_path("../.."), "../..");
	CHECK(compress_path("/.."), "/..");
	CHECK(compress_path("~/.."), "~/..");
	CHECK(compress_path("/../.."), "/../..");
	CHECK(compress_path("~/../.."), "~/../..");
	CHECK(compress_path("zeek/.."), "");
	CHECK(compress_path("zeek/../.."), "..");
	}
