# $Id: standalone.rotate-logs.bro 6811 2009-07-06 20:41:10Z robin $

@load mail-alarms

redef log_rotate_interval = 24hrs;
redef log_rotate_base_time = "0:00";
redef RotateLogs::default_postprocessor = "archive-log";

redef conn_file &rotate_interval = 12hrs;
