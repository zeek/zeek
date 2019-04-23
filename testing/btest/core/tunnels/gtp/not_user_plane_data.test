# @TEST-EXEC: zeek -r $TRACES/tunnels/gtp/gtp10_not_0xff.pcap
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: test ! -e tunnel.log

# There are GTP tunnel packets, which do not contain user plane data. Only
# those with gtp.message==0xff contain user plane data. Other GTP packets
# without user plane data are echo request, echo reply, error indication
# and stop marker (not included in trace). Those non-user plane GTP
# packets are ignored for now.
