# $Id: cluster-manager.notice.bro 6811 2009-07-06 20:41:10Z robin $

redef mail_script = "mail-alarm";
redef mail_dest = "_broctl_default_"; # Will be replace by mail script.  

# These don't get cleared because we're not seeing the actual connections. 	
redef notice_tags &read_expire = 2hrs;

