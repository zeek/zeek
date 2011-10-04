##! This strives to tune out high volume and less useful data 
##! from the notice log.

@load base/frameworks/notice
@load base/frameworks/notice/weird

redef Notice::ignored_types += {
	## Only allow these to go in the weird log.
	Weird::Weird_Activity,
};
