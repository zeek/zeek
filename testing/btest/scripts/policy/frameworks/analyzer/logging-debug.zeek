# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT
# @TEST-EXEC: mv analyzer_debug.log analyzer_debug.log-default
# @TEST-EXEC: btest-diff analyzer_debug.log-default

# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT Analyzer::DebugLogging::include_confirmations=F
# @TEST-EXEC: mv analyzer_debug.log analyzer_debug.log-dontinclude-confirmations
# @TEST-EXEC: btest-diff analyzer_debug.log-dontinclude-confirmations

# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT Analyzer::DebugLogging::include_disabling=F
# @TEST-EXEC: mv analyzer_debug.log analyzer_debug.log-dontinclude-disabling
# @TEST-EXEC: btest-diff analyzer_debug.log-dontinclude-disabling

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/socks

@load frameworks/analyzer/analyzer-debug-log

# DCE RPC violations are ignored by default. Consider violations for this
# test so that the analyzer will be disabled eventually.
redef DPD::ignore_violations -= { Analyzer::ANALYZER_DCE_RPC };
