# @TEST-DOC: Verify that repeated SSLv2 ServerHello messages do not bypass certificate processing limits.
#
# @TEST-EXEC: zeek -b -r $TRACES/tls/sslv2-repeated-server-hello.pcap %INPUT
#
# Annoying canonifier so this passes with both binpac and spicy. Just remove the source loc in parens
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed 's/ (.*)$//' | $TEST_DIFF_CANONIFIER" btest-diff-cut -m analyzer_name uid failure_reason analyzer_debug.log

@load base/protocols/ssl
@load frameworks/analyzer/debug-logging.zeek

redef Analyzer::DebugLogging::include_confirmations = F;
redef Analyzer::DebugLogging::include_disabling = F;
