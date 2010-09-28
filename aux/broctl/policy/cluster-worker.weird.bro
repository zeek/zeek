# $Id: cluster-worker.weird.bro 6811 2009-07-06 20:41:10Z robin $
#
# Important weird events are forwarded via NOTICE mechanism,
# so we are not remote printing the worker weird.log.
# (If one is never going to look at the worker weird log, it could be
# suppressed with a local notice policy).

redef Weird::weird_file &disable_print_hook;

redef notice_action_filters += 
	{
	# Not worth forwarding as they can generate a lot of load
	# if the machines gets really busy.
	[Weird::ContentGap] = ignore_notice,
	[Weird::AckAboveHole] = ignore_notice
	};

