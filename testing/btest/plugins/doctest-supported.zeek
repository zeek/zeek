# This requires Zeek with unit test support. The following errors if disabled.
# @TEST-REQUIRES: zeek --test -h >/dev/null

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Doctest
# @TEST-EXEC: cp -r %DIR/doctest-plugin/* .

# Build the plugin with unit-test support. Zeek supports it, so we should
# get runnable tests.
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# List the plugin's test names.
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Doctest" ZEEK_PLUGIN_PATH=`pwd` zeek --test -ltc | grep doctest-plugin >testnames
# @TEST-EXEC: btest-diff testnames

# The seed file affects some of the unit tests, so we unset it.
# Running the unit tests implies deterministic mode, -D.
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_PLUGIN_ACTIVATE="Demo::Doctest" ZEEK_PLUGIN_PATH=`pwd` zeek --test --test-case='doctest-plugin/*' >testresults
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-clean-doctest btest-diff testresults
