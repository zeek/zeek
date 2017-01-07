# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print (async lookup_hostname("www.icir.org"));
	print (async lookup_addr(131.159.14.1));
	}

