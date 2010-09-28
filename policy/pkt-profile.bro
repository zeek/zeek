# $Id: pkt-profile.bro 325 2004-09-03 01:33:15Z vern $

redef pkt_profile_file = open_log_file("pkt-prof");
redef pkt_profile_mode = PKT_PROFILE_MODE_SECS;
redef pkt_profile_freq = 1.0;
