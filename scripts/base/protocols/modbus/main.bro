##! Base Modbus analysis script. For now it does not do anything else than
##! activating the analyzer for connections on Modbus port 502/tcp.  

module Modbus;

export {
}

# Configure DPD and the packet filter.
redef capture_filters += { ["modbus"] = "tcp port 502" };
redef dpd_config += { [ANALYZER_MODBUS] = [$ports = set(502/tcp)] };
redef likely_server_ports += { 502/tcp };
