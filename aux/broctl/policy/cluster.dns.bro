# $Id: cluster.dns.bro 6811 2009-07-06 20:41:10Z robin $

redef DNS::dns_sessions  &read_expire = 5 mins;
redef DNS::hostile_domain_list = {};
redef DNS::logging = F;
