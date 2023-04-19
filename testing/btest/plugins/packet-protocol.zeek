# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -r $TRACES/raw_layer.pcap -e "@load policy/misc/unknown-protocols"
# @TEST-EXEC: cat conn.log > output_orig
# @TEST-EXEC: cat unknown_protocols.log > output_orig
# @TEST-EXEC: btest-diff output_orig
# @TEST-EXEC: rm -f *.log
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . PacketDemo Bar
# @TEST-EXEC: cp -r %DIR/packet-protocol-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -NN PacketDemo::Bar > output_build
# @TEST-EXEC: btest-diff output_build
#
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/raw_layer.pcap %INPUT > output_raw
# @TEST-EXEC: cat conn.log >> output_raw
# @TEST-EXEC: test ! -e unknown_protocols.log
# @TEST-EXEC: btest-diff output_raw
# @TEST-EXEC: rm -f *.log

@load policy/misc/unknown-protocols

event raw_layer_message(msg: string, protocol: count)
	{
	print fmt("raw_layer_message (Message = '%s', Protocol = %x)", msg, protocol);
	}

event llc_demo_message(dsap: count, ssap: count, control: count)
	{
	print fmt("llc_demo_message (DSAP = %x, SSAP = %x, Control = %x)",
	 dsap, ssap, control);
	}
