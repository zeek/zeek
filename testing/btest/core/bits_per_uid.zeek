# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace %INPUT bits_per_uid=32 >32
# @TEST-EXEC: btest-diff 32
# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace %INPUT bits_per_uid=64 >64
# @TEST-EXEC: btest-diff 64
# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace %INPUT bits_per_uid=96 >96
# @TEST-EXEC: btest-diff 96
# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace %INPUT bits_per_uid=128 >128
# @TEST-EXEC: btest-diff 128
# @TEST-EXEC: zeek -r $TRACES/ftp/ipv4.trace %INPUT bits_per_uid=256 >256
# @TEST-EXEC: btest-diff 256
# @TEST-EXEC: cmp 128 256

event new_connection(c: connection)
	{
	print c$uid;
	}

event file_new(f: fa_file)
	{
	print f$id;
	}
