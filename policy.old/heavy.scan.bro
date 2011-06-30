# $Id: heavy.scan.bro 4758 2007-08-10 06:49:23Z vern $

redef distinct_peers &create_expire = 10 hrs;
redef distinct_ports &create_expire = 10 hrs;
redef distinct_low_ports &create_expire = 10 hrs;
redef possible_scan_sources &create_expire = 10 hrs;
