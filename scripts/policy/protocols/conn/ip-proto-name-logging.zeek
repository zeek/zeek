##! This script adds a string version of the ip_proto field. It's not recommended
##! to load this policy and the ip_proto removal policy at the same time, as
##! conn.log will end up with useless information in the log from this field.

@load base/protocols/conn

module Conn;

redef record Info += {
	## A string version of the ip_proto field
	ip_proto_name: string &log &optional;
};

global protocol_names: table[count] of string = {
	[0] = "hopopt",
	[1] = "icmp",
	[2] = "igmp",
	[3] = "ggp",
	[4] = "ip-in-ip",
	[5] = "st",
	[6] = "tcp",
	[7] = "cbt",
	[8] = "egp",
	[9] = "igp",
	[10] = "bbc-rcc-mon",
	[11] = "nvp-ii",
	[12] = "pup",
	[13] = "argus",
	[14] = "emcon",
	[15] = "xnet",
	[16] = "chaos",
	[17] = "udp",
	[18] = "mux",
	[19] = "dcn-meas",
	[20] = "hmp",
	[21] = "prm",
	[22] = "xns-idp",
	[23] = "trunk-1",
	[24] = "trunk-2",
	[25] = "leaf-1",
	[26] = "leaf-2",
	[27] = "rdp",
	[28] = "irtp",
	[29] = "iso-tp4",
	[30] = "netblt",
	[31] = "mfe-nsp",
	[32] = "merit-inp",
	[33] = "dccp",
	[34] = "3pc",
	[35] = "idpr",
	[36] = "xtp",
	[37] = "ddp",
	[38] = "idpr-cmtp",
	[39] = "tp++",
	[40] = "il",
	[41] = "ipv6",
	[42] = "sdrp",
	[43] = "ipv6-route",
	[44] = "ipv6-frag",
	[45] = "idrp",
	[46] = "rsvp",
	[47] = "gre",
	[48] = "dsr",
	[49] = "bna",
	[50] = "esp",
	[51] = "ah",
	[52] = "i-nlsp",
	[53] = "swipe",
	[54] = "narp",
	[55] = "mobile",
	[56] = "tlsp",
	[57] = "skip",
	[58] = "ipv6-icmp",
	[59] = "ipv6-nonxt",
	[60] = "ipv6-opts",
	[61] = "host-protocol",  # Any host internal protocol
	[62] = "cftp",
	[63] = "local-network",  # Any local network
	[64] = "sat-expak",
	[65] = "kryptolan",
	[66] = "rvd",
	[67] = "ippc",
	[68] = "distributed-files",  # Any distributed file system
	[69] = "sat-on",
	[70] = "visa",
	[71] = "ipcu",
	[72] = "cpnx",
	[73] = "cphb",
	[74] = "wsn",
	[75] = "pvp",
	[76] = "br-sat-mon",
	[77] = "sun-and",
	[78] = "wb-mon",
	[79] = "wb-expak",
	[80] = "iso-ip",
	[81] = "vmtp",
	[82] = "secure-vmtp",
	[83] = "vines",
	[84] = "ttp or iptm",  # TTP was obsoleted in 3/2023, replaced with IGTM
	[85] = "nsfnet-igp",
	[86] = "dgp",
	[87] = "tcf",
	[88] = "eigrp",
	[89] = "ospf",
	[90] = "sprite-rpc",
	[91] = "larp",
	[92] = "mtp",
	[93] = "ax.25",
	[94] = "os",
	[95] = "micp",
	[96] = "scc-sp",
	[97] = "etherip",
	[98] = "encap",
	[99] = "private-encryption",  # Any private encryption scheme
	[100] = "gtmp",
	[101] = "ifmp",
	[102] = "pnni",
	[103] = "pim",
	[104] = "aris",
	[105] = "scps",
	[106] = "qnx",
	[107] = "a/n",
	[108] = "ipcomp",
	[109] = "snp",
	[110] = "compaq-peer",
	[111] = "ipx-in-ip",
	[112] = "vrrp",
	[113] = "pgm",
	[114] = "zero-hop", # Any 0-hop protocol
	[115] = "l2tp",
	[116] = "ddx",
	[117] = "iatp",
	[118] = "stp",
	[119] = "srp",
	[120] = "uti",
	[121] = "smp",
	[122] = "sm",
	[123] = "ptp",
	[124] = "is-is-over-ipv4",
	[125] = "fire",
	[126] = "crtp",
	[127] = "crudp",
	[128] = "sccopmce",
	[129] = "iplt",
	[130] = "sps",
	[131] = "pipe",
	[132] = "sctp",
	[133] = "fc",
	[134] = "rsvp-e2e-ignore",
	[135] = "mobility-header",
	[136] = "udplite",
	[137] = "mpls-in-ip",
	[138] = "manet",
	[139] = "hip",
	[140] = "shim6",
	[141] = "wesp",
	[142] = "rohc",
	[143] = "ethernet",
	[144] = "aggfrag",
	[145] = "nsh",
	[146] = "homa"
};

event new_connection(c: connection) &priority=5 {
	# In case we're the first access
	Conn::set_conn(c, F);
	if ( c$conn?$ip_proto && c$conn$ip_proto in protocol_names )
		c$conn$ip_proto_name = protocol_names[c$conn$ip_proto];
}