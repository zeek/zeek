##! This strives to tune out high volume and less useful data 
##! from the notice log.

# Remove these notices from logging since they can be too noisy.
redef Notice::ignored_types += {
	Weird::Content_Gap,
	Weird::Ack_Above_Hole,
	Weird::Retransmission_Inconsistency,
	## Only allow these to go in the weird log.
	Weird::Weird_Activity,
};
