# @TEST-EXEC: zeek -b -r $TRACES/tunnels/Teredo.pcap base/frameworks/dpd base/protocols/tunnels base/protocols/dns protocols/conn/known-services Tunnel::delay_teredo_confirmation=T "Site::local_nets+={192.168.2.0/24}"
# @TEST-EXEC: btest-diff known_services.log

# Expect known_services.log to NOT indicate any service using teredo.
