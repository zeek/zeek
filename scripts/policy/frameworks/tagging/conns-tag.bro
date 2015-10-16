##! Extend the conn log with tags for orig and resp hosts.

@load base/protocols/conn
@load base/frameworks/tagging

redef record Conn::Info += {
	orig_tags: set[string] &log &optional;
	resp_tags: set[string] &log &optional;
};

event connection_state_remove(c: connection) &priority=3
	{
	c$conn$orig_tags = Tagging::get(c$id$orig_h);
	c$conn$resp_tags = Tagging::get(c$id$resp_h);
	}
