# $Id: flag-irc.bro 4758 2007-08-10 06:49:23Z vern $
#
# include this module to flag various forms of IRC access.

@load ftp

redef FTP::hot_files +=
	  /.*eggdrop.*/
	| /.*eggsun.*/
	;

redef Hot::flag_successful_inbound_service: table[port] of string += {
	[[6666/tcp, 6667/tcp]] = "inbound IRC",
};

redef Hot::hot_dsts: table[addr] of string += {
	[bitchx.com] = "IRC source sites",
};
