# Source this script in addition to protocols/conn/community-id
# to add Community ID to notices.

# Only support loading this if the main script is also loaded.
@load base/protocols/conn
@load base/frameworks/notice

@ifdef ( CommunityID::seed )

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
		n$community_id = community_id_v1(n$conn$id);
	}
@endif
