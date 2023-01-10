# @TEST-EXEC: zeek -b  -r ${TRACES}/wikipedia.trace %INPUT
# @TEST-EXEC: mv analyzer.log analyzer.log-no-confirmations
# @TEST-EXEC: btest-diff analyzer.log-no-confirmations

# @TEST-EXEC: zeek -b  -r ${TRACES}/wikipedia.trace %INPUT Analyzer::Logging::include_confirmations=T
# @TEST-EXEC: mv analyzer.log analyzer.log-include-confirmations
# @TEST-EXEC: btest-diff analyzer.log-include-confirmations

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
