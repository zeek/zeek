# @TEST-DOC: Ensure the enum from the .bif file is available right after @load-plugin in bare mode.
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo EnumBif
# @TEST-EXEC: cp -r %DIR/enum-bif-plugin/* .
#
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT >output.abs
# @TEST-EXEC: grep '[Ee]num' loaded_scripts.log > loaded_scripts.log.abs
# @TEST-EXEC: ZEEK_PLUGIN_PATH=./build zeek -b %INPUT >output.rel
# @TEST-EXEC: grep '[Ee]num' loaded_scripts.log > loaded_scripts.log.rel
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output.abs
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -E 's/(Demo-EnumBif)\.(.*)$/\1.shared/' | $SCRIPTS/diff-remove-abspath" btest-diff loaded_scripts.log.abs
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output.rel
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -E 's/(Demo-EnumBif)\.(.*)$/\1.shared/' | $SCRIPTS/diff-remove-abspath" btest-diff loaded_scripts.log.rel

@load misc/loaded-scripts

@load ./enum-before-load-plugin

@load-plugin Demo::EnumBif

@load ./enum-after-load-plugin

event zeek_init()
	{
	print(EnumBif::MyEnumA);
	print enum_names(EnumBif::MyEnum);
	}

@load-plugin Demo::EnumBif

@load ./enum-after-load-plugin-end

# @TEST-START-FILE enum-before-load-plugin.zeek
# empty
# @TEST-END-FILE

# @TEST-START-FILE enum-after-load-plugin.zeek
# empty
# @TEST-END-FILE

# @TEST-START-FILE enum-after-load-plugin-end.zeek
# empty
# @TEST-END-FILE
