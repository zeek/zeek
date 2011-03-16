# $Id: heavy.irc.bro 4723 2007-08-07 18:14:35Z vern $

redef active_users &persistent &read_expire = 1 days;
redef active_channels &persistent &read_expire = 1 days;
