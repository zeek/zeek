# @TEST-DOC: Ensures global_ids doesn't segfault in global scope; regression test for #5197
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

global gi = global_ids();
