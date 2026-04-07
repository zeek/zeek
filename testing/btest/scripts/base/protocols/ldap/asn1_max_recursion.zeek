# @TEST-DOC: Tests that limiations on ASN.1 message recursion work correctly and deeply nested searches don't result in heap-buffer overflows.
#
# @TEST-REQUIRES: have-spicy
# @TEST-REQUIRES: test "$($BUILD/zeek-config --build_type)" = "debug"
#
# @TEST-EXEC: zeek -B spicy -r ${TRACES}/ldap/asn1-max-recursion.pcap
# @TEST-EXEC: grep "exceeded max recursion depth" debug.log > debug-filtered.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff debug-filtered.log
