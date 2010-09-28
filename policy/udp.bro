# $Id: udp.bro 1103 2005-03-17 09:18:28Z vern $

@load udp-common

redef capture_filters += { ["udp"] = "udp" };
