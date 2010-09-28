# $Id: cluster.scan.bro 6860 2009-08-14 19:01:47Z robin $

redef addr_scan_trigger = 3;  
redef ignore_scanners_threshold = 500; 

redef pre_distinct_peers &read_expire = 12hrs;

redef distinct_backscatter_peers &read_expire = 30mins;
redef distinct_peers &read_expire = 30mins;
redef distinct_ports &read_expire = 30mins;
redef distinct_low_ports &read_expire = 30mins;
redef possible_scan_sources &read_expire = 30mins;

