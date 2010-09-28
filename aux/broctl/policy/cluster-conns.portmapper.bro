# $Id: cluster-conns.portmapper.bro 6811 2009-07-06 20:41:10Z robin $

redef did_pm_log &persistent &synchronized &read_expire = 1 day &synchronized;
