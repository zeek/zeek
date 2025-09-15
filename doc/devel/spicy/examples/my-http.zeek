event MyHTTP::request_line(c: connection, method: string, uri: string, version: string)
	{
	print fmt("Zeek saw from %s: %s %s %s", c$id$orig_h, method, uri, version);
	}
