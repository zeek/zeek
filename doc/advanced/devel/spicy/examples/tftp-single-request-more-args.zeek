event tftp::request(c: connection, is_orig: bool, filename: string, mode: string)
	{
	print "TFTP request", c$id, is_orig, filename, mode;
	}
