# Source this script to add Community ID to notices.
# This script will automatically load the main community-id script.

@load base/protocols/conn
@load base/frameworks/notice
@load policy/protocols/conn/community-id-logging

module CommunityID::Notice;

export {
	# Turn notice support on/off at runtime. When disabled,
	# this still leaves the `community_id` string in the notice
	# log, just unset.
	option enabled: bool = T;

	redef record Notice::Info += {
		community_id: string &optional &log;
	};
}

hook Notice::notice(n: Notice::Info)
	{
	if ( CommunityID::Notice::enabled && n?$conn && n$conn?$conn )
		{
		local info = n$conn$conn;
		# This is set during new_connection(), so it should
		# always be there, but better safe than sorry.
		if ( info?$community_id )
			n$community_id = info$community_id;
		}
	}
