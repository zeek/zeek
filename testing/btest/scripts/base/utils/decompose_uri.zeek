# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

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
	}

