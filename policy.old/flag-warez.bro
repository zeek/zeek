# $Id: flag-warez.bro 416 2004-09-17 03:52:28Z vern $
#
# include this module to flag various forms of Warez access.

@load hot-ids
@load ftp

redef FTP::hot_files += /.*[wW][aA][rR][eE][zZ].*/ ;

redef always_hot_ids += { "warez", "hanzwarez", "zeraw", };
redef hot_ids += { "warez", "hanzwarez", "zeraw", };
