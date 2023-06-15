# @TEST-DOC: Loading two plugins with the same name triggers a warning.

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/pktsrc-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: cp -R build build_backup
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd`/build_backup:`pwd`/build zeek -NN Demo::Foo  >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
