##! These are default settings for the Notice framework that strive to 
##! tune out high volume and less useful data from the logs.

@load weird
@load dpd

# Remove these notices from logging since they can be too noisy.
redef Notice::action_filters += {
	[[Weird::ContentGap, Weird::AckAboveHole]] = Notice::ignore_action,
	[[DPD::ProtocolViolation]] = Notice::ignore_action,
};
