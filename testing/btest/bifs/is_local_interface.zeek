#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print is_local_interface(127.0.0.1);
	print is_local_interface(1.2.3.4);
	print is_local_interface([2607::a:b:c:d]);
	print is_local_interface([::1]);
	}
