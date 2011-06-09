##! This strives to tune out high volume and less useful data 
##! from the notice log.

@load notice

# Load the policy scripts where the notices are defined.
@load weird
@load dpd

# Remove these notices from logging since they can be too noisy.
redef Notice::action_filters += {
	[[Weird::ContentGap, Weird::AckAboveHole]] = Notice::ignore_action,
	[[DPD::ProtocolViolation]] = Notice::ignore_action,
};
