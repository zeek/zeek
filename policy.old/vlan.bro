# $Id: vlan.bro 416 2004-09-17 03:52:28Z vern $

redef restrict_filters += { ["vlan"] = "vlan" };

redef encap_hdr_size = 4;
