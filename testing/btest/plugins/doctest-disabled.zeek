# This requires Zeek with unit test support. The following errors if disabled.
# @TEST-REQUIRES: zeek --test -h >/dev/null

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Doctest
# @TEST-EXEC: cp -r %DIR/doctest-plugin/* .

# Build the plugin without unit-test support.
# @TEST-EXEC: ./configure --disable-cpp-tests --zeek-dist=${DIST} && make
#
# List the plugin's test names -- there shouldn't be any.
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Doctest" ZEEK_PLUGIN_PATH=`pwd` zeek --test -ltc | grep doctest-plugin >testnames || true
# @TEST-EXEC: btest-diff testnames
