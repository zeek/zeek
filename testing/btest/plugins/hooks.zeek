# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy  # This test logs loaded scripts, so disable it if Spicy and the associated plugin are unavailable.
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Hooks
# @TEST-EXEC: cp -r %DIR/hooks-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/http/get.trace %INPUT s1.sig 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: btest-diff output

@load-sigs s2

@TEST-START-FILE s1.sig
# Just empty.
@TEST-END-FILE

@TEST-START-FILE s2.sig
# Just empty.
@TEST-END-FILE

