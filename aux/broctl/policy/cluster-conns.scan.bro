# $Id: cluster-conns.scan.bro 6811 2009-07-06 20:41:10Z robin $

# Port scans
redef distinct_ports &persistent &synchronized;
redef distinct_low_ports &persistent &synchronized;
redef possible_scan_sources &persistent &synchronized;
redef scan_triples &persistent &synchronized;
