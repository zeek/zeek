#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print compress_path("./../foo");
	print compress_path("././../foo");
	}
