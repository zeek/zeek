#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = 192.168.0.2;
	local b = 257/tcp;
	print fmt_ftp_port(a, b);

	a = [fe80::1234];
	print fmt_ftp_port(a, b);
	}
