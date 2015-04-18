# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC-FAIL: BRO_PLUGIN_PATH=`pwd` bro -NN Demo::Foo >tmp 2>&1
# @TEST-EXEC: cat tmp | sed 's/Demo-Foo[-a-zA-Z0-9_.]*/XXX/' >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

( echo '#define BRO_PLUGIN_API_VERSION 42'; cat src/Plugin.cc; ) >src/Plugin.cc.tmp && mv src/Plugin.cc.tmp src/Plugin.cc
