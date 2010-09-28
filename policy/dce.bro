# $Id:$

redef capture_filters += { ["dce"] = "port 135" };

global dce_ports = { 135/tcp } &redef;
redef dpd_config += { [ANALYZER_DCE_RPC] = [$ports = dce_ports] };

# No default implementation for events.
