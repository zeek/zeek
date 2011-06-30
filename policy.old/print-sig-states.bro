# $Id: print-sig-states.bro 491 2004-10-05 05:44:59Z vern $
#
# Simple profiling script for periodicaly dumping out signature-matching
# statistics.

global sig_state_stats_interval = 5 mins;
global sig_state_file = open_log_file("sig-states");

event dump_sig_state_stats()
	{
	dump_rule_stats(sig_state_file);
	schedule sig_state_stats_interval { dump_sig_state_stats() };
	}

event bro_init()
	{
	schedule sig_state_stats_interval { dump_sig_state_stats() };
	}
