# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT
# @TEST-EXEC: mv analyzer_failed.log analyzer_failed.log-default
# @TEST-EXEC: btest-diff analyzer_failed.log-default

# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT Analyzer::Logging::include_confirmations=T
# @TEST-EXEC: mv analyzer_failed.log analyzer_failed.log-include-confirmations
# @TEST-EXEC: btest-diff analyzer_failed.log-include-confirmations

# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT Analyzer::Logging::include_disabling=T
# @TEST-EXEC: mv analyzer_failed.log analyzer_failed.log-include-disabling
# @TEST-EXEC: btest-diff analyzer_failed.log-include-disabling

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/socks

# DCE RPC violations are ignored by default. Consider violations for this
# test so that the analyzer will be disabled eventually.
redef DPD::ignore_violations -= { Analyzer::ANALYZER_DCE_RPC };
