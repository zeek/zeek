# $Id: cluster-manager.mail-alarms.bro 6811 2009-07-06 20:41:10Z robin $

@load rotate-logs

redef MailAlarms::output &rotate_interval = 12hrs;
