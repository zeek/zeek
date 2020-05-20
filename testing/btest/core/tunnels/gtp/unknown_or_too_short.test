# @TEST-EXEC: zeek -C -r $TRACES/tunnels/gtp/gtp9_unknown_or_too_short_payload.pcap
# @TEST-EXEC: btest-diff dpd.log
# @TEST-EXEC: btest-diff tunnel.log

# Packet 11, epoch time 1333458853.075889 is malformed. Only 222 byte are
# captured, although according to the IP header a full packet should be
# available. In Sessions.cc this throws a weird message at line 710.
# Packet 12, epoch time 1333458853.075904 is malformed. The user plane
# packet is no IPv4 nor IPv6 packet. Very probably this is a follow up
# issue on a problem of the user plane packet before it was put into the
# tunnel. The user plane packet may got corrupt and then put into 2 tunnel
# packets, here packet 11 and 12, and in packet 12 the user plane data is
# part of the remainder of the broken user plane packet of packet 11.
