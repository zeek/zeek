# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Demo Hooks
# @TEST-EXEC: cp -r %DIR/hooks-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_ACTIVATE="Demo::Hooks" BRO_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/http/get.trace %INPUT 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: btest-diff output

@unload base/misc/version
@load base/init-default
