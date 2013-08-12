# Capture TCP fragments, but not UDP (or ICMP), since those are a lot more
# common due to high-volume, fragmenting protocols such as NFS :-(.

# This normally isn't used because of the default open packet filter 
# but we set it anyway in case the user is using a packet filter.
# Note: This was removed because the default model now is to have a wide
#       open packet filter.
#redef capture_filters += { ["frag"] = "(ip[6:2] & 0x3fff != 0) and tcp" };

## Shorten the fragment timeout from never expiring to expiring fragments after
## five minutes.
redef frag_timeout = 5 min;
