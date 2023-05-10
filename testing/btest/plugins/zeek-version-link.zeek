# @TEST-DOC: Poking at internals: Expect an undefined zeek_version_X_Y_Z_plugin symbol in the plugin's .so/.dynlib. If this test turns out to be brittle, remove it, but we lost the mechanism.
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/pktsrc-plugin/* .
# @TEST-EXEC: (./configure --zeek-dist=${DIST} && VERBOSE=1 make) >&2
# @TEST-EXEC: nm -u build/lib/Demo-Foo* > undefined.out
# @TEST-EXEC:  grep -E 'zeek_version_[0-9]+_[0-9]+_[0-9]+.*_plugin_[0-9]+' undefined.out
