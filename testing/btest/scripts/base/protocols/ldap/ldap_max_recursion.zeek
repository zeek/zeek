# @TEST-DOC: Tests that limiations on LDAP search filter recursion work correctly and deeply nested searches don't result in heap-buffer overflows.
#
# @TEST-REQUIRES: have-spicy

# @TEST-EXEC: zeek -B spicy -r ${TRACES}/ldap/ldap-max-recursion.pcap %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath" btest-diff output

event analyzer_violation_info(atype: AllAnalyzers::Tag,
    info: AnalyzerViolationInfo)
	{
	print info$c$uid, info$reason;
	}
