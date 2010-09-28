@load dns-common-summary

redef DNS_common_summary::dns_summary_log = open_log_file("netbios-ns-summary");
redef DNS_common_summary::server_ports = { 137/udp };

redef capture_filters += {
	["netbios-ns"] = "udp port 137",
};

