# @TEST-EXEC: zeek -r ${TRACES}/socks.trace %INPUT
# @TEST-EXEC: btest-diff analyzer_failed.log

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/socks

# DCE RPC violations are ignored by default. Consider violations for this
# test so that the analyzer will be disabled eventually.
redef DPD::ignore_violations -= { Analyzer::ANALYZER_DCE_RPC };
