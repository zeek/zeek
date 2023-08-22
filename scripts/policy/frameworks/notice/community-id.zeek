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
	if ( CommunityID::Notice::enabled && n?$conn )
		n$community_id = community_id_v1(n$conn$id, CommunityID::seed, CommunityID::do_base64);
	}
