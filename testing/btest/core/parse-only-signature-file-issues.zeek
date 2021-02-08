# @TEST-DOC: ``zeek -a`` should parse scripts and also still detect signature file issues.

# @TEST-EXEC-FAIL: zeek -b -a -s nope %INPUT >missing-sig-file 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff missing-sig-file

# @TEST-EXEC-FAIL: zeek -b -a test.zeek >invalid-sig-file 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff invalid-sig-file

@TEST-START-FILE test.zeek
@load-sigs test.sig
@TEST-END-FILE

@TEST-START-FILE test.sig
invalid
@TEST-END-FILE
