# $Id: standalone.notice.bro 6811 2009-07-06 20:41:10Z robin $

redef mail_script = "mail-alarm";
redef mail_dest = "_broctl_default_"; # Will be replaced by mail script.  

redef use_tagging = T;	

