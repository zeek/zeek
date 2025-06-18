# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
# @TEST-REQUIRES: have-spicy  # This test logs loaded scripts, so disable it if Spicy and the associated plugin are unavailable.
# @TEST-REQUIRES: have-zeromq  # This test logs loaded scripts, so disable it if ZeroMQ isn't available.
# @TEST-REQUIRES: ! have-spicy-ssl  # Enabling Spicy SSL changes baselines and thus changes raised events. Skip in this case.
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Hooks
# @TEST-EXEC: cp -r %DIR/hooks-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/http/get.trace %INPUT s1.sig 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-timestamps btest-diff output

@load base/protocols/conn
@load base/protocols/http

@load-sigs s2

# @TEST-START-FILE s1.sig
# Just empty.
# @TEST-END-FILE

# @TEST-START-FILE s2.sig
# Just empty.
# @TEST-END-FILE

# The built-in JavaScript plugin's __load__.zeek file uses cat() in its
# __load__.zeek file, causing subtle baseline diffs as it is not enabled
# on all platforms. Provide a mock file that is picked up before the
# plugin's file due to `.` being first in ZEEKPATH. Sorry.
# @TEST-START-FILE Zeek_JavaScript/__load__.zeek
module JavaScript;
export {
	global files: vector of string;
}
# @TEST-END-FILE
