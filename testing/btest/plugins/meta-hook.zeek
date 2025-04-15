# @TEST-DOC: Plugin testing the meta hooks specifically. This is a regression test for these being enabled with HookCallFunction() instead.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Meta_Hooks
# @TEST-EXEC: cp -r %DIR/meta-hook-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT >out-none
# @TEST-EXEC: TEST_META_HOOK_PRE=1 ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT >out-pre-only
# @TEST-EXEC: TEST_META_HOOK_POST=1 ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT >out-post-only
# @TEST-EXEC: TEST_META_HOOK_PRE=1 TEST_META_HOOK_POST=1 ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT >out-both
#
# @TEST-EXEC: btest-diff out-none
# @TEST-EXEC: btest-diff out-pre-only
# @TEST-EXEC: btest-diff out-post-only
# @TEST-EXEC: btest-diff out-both

@load-plugin Demo::Meta_Hooks

redef allow_network_time_forward = F;

event zeek_init()
	{
	print "zeek_init()";
	}
