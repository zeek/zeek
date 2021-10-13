# Test the x509_check_hostname bif.

# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

function check_it(host: string, cert: string)
	{
	print host, cert, x509_check_hostname(host, cert);
	}

event zeek_init()
	{
	check_it("hi", "www.zeek.org");
	check_it("ww.zeek.org", "www.zeek.org");
	check_it("www.zeek.org", "www.zeek.org");
	check_it("www.zeek.org", "*");
	check_it("www.zeek.org", "zeek.org");
	check_it("www.zeek.org", "*.zeek.org");
	check_it("www.zeek.org", "a*.zeek.org");
	check_it("www.zeek.org", "ww*.zeek.org");
	check_it("www.zeek.org", "wa*.zeek.org");
	check_it("www.zeek.org", "ww*.leek.com");
	check_it("www.zeek.org", "*.*.com");
	check_it("", "");
	check_it("www.zeek.org\x00testing", "*.zeek.org");
	check_it("zeek.org", "zeek.org");
	check_it("zeek.org", "*.org");
	check_it("a.b.zeek.org", "*.b.zeek.org");
	check_it("a.b.zeek.org", "*.zeek.org");
	check_it("a.b.zeek.org", "*.a.zeek.org");
	}
