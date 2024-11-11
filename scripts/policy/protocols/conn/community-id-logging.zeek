##! Adds community hash IDs to conn.log.
@load base/protocols/conn

module CommunityID;

export {
	# An unsigned 16-bit number to seed our hashing
	option seed: count = 0;

	# Whether to add a base64 pass over the hash digest.
	# Enabled by default, since it shortens the output.
	option do_base64: bool = T;

	# Add the ID string field to the connection log record.
	redef record Conn::Info += {
		community_id: string &optional &log;
	};
}

module Conn;

event new_connection(c: connection) &priority=5
	{
	Conn::set_conn(c, F);  # likely first to access :-/
	c$conn$community_id = community_id_v1(c$id, CommunityID::seed, CommunityID::do_base64);
	}
