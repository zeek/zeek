# Capture TCP fragments, but not UDP (or ICMP), since those are a lot more
# common due to high-volume, fragmenting protocols such as NFS :-(.

redef capture_filters += { ["frag"] = "(ip[6:2] & 0x3fff != 0) and tcp" };

redef frag_timeout = 5 min;
