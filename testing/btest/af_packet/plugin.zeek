# @TEST-DOC: On Linux, test AF_PACKET support exists when enabled and the AF_Packet module is available in script land.
# @TEST-REQUIRES: ${SCRIPTS}/have-af-packet
# @TEST-EXEC: zeek -N Zeek::AF_Packet
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

# Print some defaults for smoke checking.
print "buffer_size", AF_Packet::buffer_size;
print "enable_fanout", AF_Packet::enable_fanout;
print "fanout_mode", AF_Packet::fanout_mode;
