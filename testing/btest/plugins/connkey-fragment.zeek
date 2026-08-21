# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/connkey-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -C -r $TRACES/ipv4/fragmented-1.pcap %INPUT >>output
# @TEST-EXEC: btest-diff output

redef ConnKey::factory = ConnKey::CONNKEY_FOO;

event zeek_done()
	{
	print "done";
	}
