# $Id: heavy-analysis.bro 2771 2006-04-18 23:53:09Z vern $
#
# Loading this files enables somewhat more accurate, yet also significantly
# more expensive, analysis (in terms of memory as well as CPU time).
#
# This script only sets core-level options.  Script-level timeouts are
# adjusted in heavy.*.bro, loaded via Bro's prefix mechanism.  To make this
# work, the prefix has to be set *before* reading other scripts, either by
# loading this script first of all, or by manually putting a @prefix
# at the start of Bro's configuration.

@prefixes += heavy

redef tcp_SYN_timeout = 120 secs;
redef tcp_session_timer = 30 secs;
redef tcp_connection_linger = 30 secs;
redef tcp_attempt_delay = 300 secs;
redef tcp_close_delay = 15 secs;
redef tcp_reset_delay = 15 secs;
redef tcp_partial_close_delay = 10 secs;

redef max_timer_expires = 32;

redef tcp_inactivity_timeout = 2 hrs;
redef udp_inactivity_timeout = 1 hrs;
redef icmp_inactivity_timeout = 1 hrs;
