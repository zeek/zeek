# $Id: notice-policy.bro 4758 2007-08-10 06:49:23Z vern $

# Examples of using notice_policy and other mechanisms to filter out
# alarms that are not interesting.

# Note: this file is not self-contained, in that it refers to Notice
# names that will only be defined if you've loaded other files (e.g.,
# print-resources for the ResourceSummary notice).  The full list of
# policy files it needs is:
#
#	blaster.bro
#	conn.bro
#	http-request.bro
#	netstats.bro
#	print-resources.bro
#	trw.bro
#	weird.bro


# Remove these notices from logging since they can be too noisy.
redef notice_action_filters += {
        [[Weird::ContentGap, Weird::AckAboveHole]] = ignore_notice,
};

# Send these only to the notice log, not the alarm log.
redef notice_action_filters += {
        [[Drop::AddressDropIgnored, DroppedPackets,
	  ResourceSummary, W32B_SourceRemote,
	  TRW::TRWScanSummary, Scan::BackscatterSeen,
	  Weird::WeirdActivity,
	  Weird::RetransmissionInconsistency]] = file_notice,
};

# Other example use of notice_action_filters:
#
# To just get a summary Notice when Bro is shutdown/checkpointed, use
# tally_notice_type, such as:
#redef notice_action_filters += {
# 	[[RetransmissionInconsistency, ContentGap, AckAboveHole]] =
#	 	tally_notice_type,
#};

# To get a summary once every hour per originator, use notice_alarm_per_orig,
# such as:
#redef notice_action_filters += {
# 	[[ BackscatterSeen, RetransmissionInconsistency]] =
# 		notice_alarm_per_orig,
#};


# Fine-grained filtering of specific alarms.
redef notice_policy += {

	# Connections to 2766/tcp ("Solaris listen service") appear
	# nearly always actually due to P2P apps.
        [$pred(n: notice_info) =
		{
		return n$note == SensitiveConnection &&
 		       /Solaris listen service/ in n$msg;
		},
         $result = NOTICE_FILE,
         $priority = 1],

	# Ignore sensitive URLs that end in .gif, .jpg, .png
	[$pred(n: notice_info) =
		{
		return n$note == HTTP::HTTP_SensitiveURI &&
		       n$URL == /.*\.(gif|GIF|png|PNG|jpg|JPG)/; 
		},
	 $result = NOTICE_FILE,
	 $priority = 1],
};
