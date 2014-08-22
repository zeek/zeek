# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin Demo Hooks
# @TEST-EXEC: cp -r %DIR/hooks-plugin/* .
# @TEST-EXEC: make BRO=${DIST}
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -r $TRACES/http/get.trace %INPUT 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: btest-diff output

