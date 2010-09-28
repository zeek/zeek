@load dns-common-summary

redef DNS_common_summary::log = open_log_file("dns-summary");
redef DNS_common_summary::server_ports = { 53/udp, 53/tcp };

redef capture_filters = {
	["dns"] = "port 53",
};
