# $Id: gnutella.bro 4017 2007-02-28 07:11:54Z vern $

redef capture_filters += { ["gnutella"] = "port 6346 or port 8436" };

global gnutella_ports = { 6346/tcp, 8436/tcp } &redef;
redef dpd_config += { [ANALYZER_GNUTELLA] = [$ports = gnutella_ports] };

event gnutella_text_msg(c: connection, orig: bool, headers: string)
	{
	if ( orig )
		print fmt("gnu txt %s -> %s %s", c$id$orig_h, c$id$resp_h, headers);
	else
		print fmt("gnu txt %s -> %s %s", c$id$resp_h, c$id$orig_h, headers);
	}


event gnutella_binary_msg(c: connection, orig: bool, msg_type: count,
				ttl: count, hops: count, msg_len: count,
				payload: string, payload_len: count,
				trunc: bool, complete: bool)
	{
	local s = "";

	if ( orig )
		s = fmt("gnu bin %s -> %s", c$id$orig_h, c$id$resp_h);
	else
		s = fmt("gnu bin %s -> %s", c$id$resp_h, c$id$orig_h);

	print fmt("%s %d %d %d %d %d %d %d %s",
			s, msg_type, ttl, hops, msg_len,
			trunc, complete, payload_len, payload);
	}


event gnutella_partial_binary_msg(c: connection, orig: bool,
					msg: string, len: count)
	{
	if ( orig )
		print fmt("gnu pbin %s -> %s", c$id$orig_h, c$id$resp_h);
	else
		print fmt("gnu pbin %s -> %s", c$id$resp_h, c$id$orig_h);
	}


event gnutella_establish(c: connection)
	{
	print fmt("gnu est %s <-> %s", c$id$orig_h, c$id$resp_h);
	}


event gnutella_not_establish(c: connection)
	{
	print fmt("gnu !est %s <-> %s", c$id$orig_h, c$id$resp_h);
	}


event gnutella_http_notify(c: connection)
	{
	print fmt("gnu http %s/%s <-> %s/%s", c$id$orig_h, c$id$orig_p,
			c$id$resp_h, c$id$resp_p);
	}
