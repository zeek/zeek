# @TEST-DOC: Tests that limiations on ASN.1 message recursion work correctly and deeply nested searches don't result in heap-buffer overflows.
#
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -r ${TRACES}/ldap/asn1-max-recursion.pcap %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff output

event analyzer_violation_info(atype: AllAnalyzers::Tag,
    info: AnalyzerViolationInfo)
	{
	print info$c$uid, info$reason;
	}
