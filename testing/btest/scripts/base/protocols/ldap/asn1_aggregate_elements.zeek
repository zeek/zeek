# @TEST-DOC: Test that LDAP ASN.1 aggregate parsing enforces a total child element limit.
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -C -r $TRACES/ldap/asn1-aggregate-elements.pcap %INPUT >output
# @TEST-EXEC: test ! -f analyzer_debug.log
#
# @TEST-EXEC: zeek -b -C -r $TRACES/ldap/asn1-aggregate-elements.pcap LDAP::max_asn1_aggregate_elements=500 %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-canonifier-spicy btest-diff-cut -m analyzer_debug.log

@load base/protocols/ldap
@load frameworks/analyzer/debug-logging

redef Analyzer::DebugLogging::include_confirmations = F;
redef Analyzer::DebugLogging::include_disabling = F;
