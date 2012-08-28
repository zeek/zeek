##! Base DNP3 analysis script. For now it does not do anything else than
##! activating the analyzer for connections on DNP port 20000/tcp.  

module DNP3;

export {
}

# Configure DPD and the packet filter.
redef capture_filters += { ["dnp3"] = "tcp port 20000" };
redef dpd_config += { [ANALYZER_DNP3] = [$ports = set(20000/tcp)] };
redef likely_server_ports += { 20000/tcp };
