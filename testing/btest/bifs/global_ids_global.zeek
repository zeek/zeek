# @TEST-DOC: Ensures global_ids doesn't segfault in global scope; regression test for #5197
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

global gi = global_ids();
