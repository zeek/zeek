# $Id: cluster-proxy.rotate-logs.bro 6811 2009-07-06 20:41:10Z robin $

redef log_rotate_interval = 24 hrs;
redef log_rotate_base_time = "0:00";
redef RotateLogs::default_postprocessor = "delete-log";
