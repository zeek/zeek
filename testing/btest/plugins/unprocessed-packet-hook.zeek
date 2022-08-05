# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Unprocessed_Packet
# @TEST-EXEC: cp -r %DIR/unprocessed-packet-hook-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Unprocessed_Packet" ZEEK_PLUGIN_PATH=`pwd` zeek -c unprocessed.pcap -b -r $TRACES/cisco-fabric-path.pcap %INPUT 2>&1 > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: hexdump -C unprocessed.pcap > unprocessed.pcap.hex
# @TEST-EXEC: btest-diff unprocessed.pcap.hex

@load base/init-default
