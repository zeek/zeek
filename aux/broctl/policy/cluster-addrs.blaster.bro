# $Id: cluster-addrs.blaster.bro 6811 2009-07-06 20:41:10Z robin $

redef w32b_scanned &persistent &synchronized;
redef w32b_reported &persistent &synchronized &read_expire = 7 days;
