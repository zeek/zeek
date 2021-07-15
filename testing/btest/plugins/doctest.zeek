# This requires a Zeek build with unit test support
# @TEST-REQUIRES: zeek --test -h

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Doctest
# @TEST-EXEC: cp -r %DIR/doctest-plugin/* .
# @TEST-EXEC: ./configure --enable-cpp-tests --zeek-dist=${DIST} && make
#
# List the plugin's test names.
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Doctest" ZEEK_PLUGIN_PATH=`pwd` zeek --test -ltc | grep doctest-plugin >testnames
# @TEST-EXEC: btest-diff testnames

# The seed file affects some of the unit tests, so we unset it.
# Running the unit tests implies deterministic mode, -D.
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_PLUGIN_ACTIVATE="Demo::Doctest" ZEEK_PLUGIN_PATH=`pwd` zeek --test --test-case='doctest-plugin/*' >testresults
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-remove-doctest-skippedcount btest-diff testresults
