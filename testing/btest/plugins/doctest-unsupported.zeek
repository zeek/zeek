# This requires Zeek without unit test support. The following errors if enabled.
# @TEST-REQUIRES: ! zeek --test -h >/dev/null

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Doctest
# @TEST-EXEC: cp -r %DIR/doctest-plugin/* .

# Build the plugin without disabling unit testing. Zeek doesn't support it,
# so the plugin should automatically build without it.
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# List the plugin's test names -- there shouldn't be any.
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Doctest" ZEEK_PLUGIN_PATH=`pwd` zeek --test -ltc | grep doctest-plugin >testnames || true
# @TEST-EXEC: btest-diff testnames
