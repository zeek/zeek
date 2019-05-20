#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print parse_ftp_port("192,168,0,2,1,1");

	print parse_eftp_port("|1|192.168.0.2|257|");
	print parse_eftp_port("|2|fe80::12|1234|");

	print parse_ftp_pasv("227 Entering Passive Mode (192,168,0,2,1,1)");

	print parse_ftp_epsv("229 Entering Extended Passive Mode (|||1234|)");
	}
