# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin  -u . Zeek AsciiReader 2>&1 > /dev/null
# @TEST-EXEC: cp -r %DIR/conflict-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC-FAIL: ZEEK_PLUGIN_PATH=`pwd` zeek -NN >> output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
