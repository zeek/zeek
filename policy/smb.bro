# $Id:$

redef capture_filters += { ["smb"] = "port 445" };

global smb_ports = { 445/tcp } &redef;
redef dpd_config += { [ANALYZER_SMB] = [$ports = smb_ports] };

# No default implementation for events.
