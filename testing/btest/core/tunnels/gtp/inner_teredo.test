# @TEST-EXEC: zeek -r $TRACES/tunnels/gtp/gtp8_teredo.pcap "Tunnel::delay_teredo_confirmation=F"
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log

# GTP packets may carry Teredo packets.  Toggled the delay teredo confirmation
# option so that it shows in the service field (in one case the inner
# connection of the teredo packet is carried over differing outer connections).
