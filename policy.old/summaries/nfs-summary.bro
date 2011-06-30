@load sun-rpc-summary

redef SUN_RPC_summary::log = open_log_file("nfs-summary");

redef capture_filters = {
	["nfs"] = "port 2049",
	# UDP packets are often fragmented
	["nfs-frag"] = "ip[6:2] & 0x1fff != 0",
};
