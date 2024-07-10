# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT
# @TEST-EXEC: mv analyzer.log analyzer.log-default
# @TEST-EXEC: btest-diff analyzer.log-default

# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT Analyzer::Logging::include_confirmations=T
# @TEST-EXEC: mv analyzer.log analyzer.log-include-confirmations
# @TEST-EXEC: btest-diff analyzer.log-include-confirmations

# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT Analyzer::Logging::include_disabling=F
# @TEST-EXEC: mv analyzer.log analyzer.log-no-disabling
# @TEST-EXEC: btest-diff analyzer.log-no-disabling

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/socks

# DCE RPC violations are ignored by default. Consider violations for this
# test so that the analyzer will be disabled eventually.
redef DPD::ignore_violations -= { Analyzer::ANALYZER_DCE_RPC };
