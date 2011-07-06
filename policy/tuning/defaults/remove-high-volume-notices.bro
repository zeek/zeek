##! This strives to tune out high volume and less useful data 
##! from the notice log.

@load notice

# Load the policy scripts where the notices are defined.
@load frameworks/notice/weird

# Remove these notices from logging since they can be too noisy.
redef Notice::ignored_types += {
	Weird::ContentGap,
	Weird::AckAboveHole,
	Weird::RetransmissionInconsistency,
	Weird::WeirdActivity, # Only allow these to go in the weird log.
};