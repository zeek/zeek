# @TEST-DOC: A plugin providing an analyzer implementing DeliverPacket() and DeliverSkippedPacket() and using HookSetupAnalyzer() to attach it to every new connection.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Hooks
# @TEST-EXEC: cp -r %DIR/deliver-skipped-packet-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip4-tcp-bad-chksum.pcap %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip4-tcp-good-chksum.pcap %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip4-udp-bad-chksum.pcap %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip4-icmp-bad-chksum.pcap %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip6-icmp6-bad-chksum.pcap %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/chksums/ip6-icmp6-good-chksum.pcap %INPUT >>output
#
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/http/get.trace %INPUT >>output
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

event zeek_init()
	{
	print packet_source()$path;
	}

event zeek_done()
	{
	print "===";
	}
