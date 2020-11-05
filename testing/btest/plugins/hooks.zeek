# @TEST-REQUIRES: test "${ZEEK_INLINE}" != "1"
# @TEST-REQUIRES: test "${ZEEK_XFORM}" != "1"
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Hooks
# @TEST-EXEC: cp -r %DIR/hooks-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/http/get.trace %INPUT 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: btest-diff output

@unload base/misc/version
@load base/init-default
