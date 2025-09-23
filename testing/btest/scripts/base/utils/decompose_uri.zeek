# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff .stderr

@load base/utils/urls

function dc(s: string)
	{
	print fmt("%s", s);
	print fmt("    -> %s", decompose_uri(s));
	print "";
	}

event zeek_init()
	{
	dc("https://www.bro.org:42/documentation/faq.html?k1=v1&k2=v2");
	dc("");
	dc("https://");
	dc("https://www.bro.org");
	dc("https://www.bro.org/");
	dc("https://www.bro.org:42");
	dc("https://www.bro.org:42/");
	dc("https://www.bro.org/documentation");
	dc("https://www.bro.org/documentation/");
	dc("https://www.bro.org/documentation/faq");
	dc("https://www.bro.org/documentation/faq.html");
	dc("https://www.bro.org/documentation/faq.html?");
	dc("https://www.bro.org/documentation/faq.html?k=v");
	dc("https://www.bro.org/documentation/faq.html?k=");
	dc("https://www.bro.org/documentation/faq.html?=v");
	dc("file:///documentation/faq.html?=v");
	dc("www.bro.org/?foo=bar");

	# Bracketed IPv6
	dc("http://[::1]:8080/?foo=bar&baz=qux");
	dc("http://[::1]/foo/bar");
	dc("http://[::1]/foo/bar");
	dc("[::1]:80/test/a/b.exe?a=b");

	# Un-bracketed is ambiguous, but not causing errors.
	dc("http://beeb:deed::1/test");
	dc("http://beeb:deed::1:8080/test");

	# Ensure colons in path or query parameters do not
	# cause trouble.
	dc("https://en.wikipedia.org/wiki/Template:Welcome");
	dc("https://[::1]:8080/wiki/Template:Welcome");
	dc("https://[::1]:8080/wiki/Template:Welcome?key=:&value=:");
	}

