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

event new_connection(c: connection) &priority=5
	{
	c$conn$community_id = community_id_v1(c$id, CommunityID::seed, CommunityID::do_base64);
	}
