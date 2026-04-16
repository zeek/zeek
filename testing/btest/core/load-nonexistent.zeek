# @TEST-DOC: Verify that loading a non-existent script still produces an error.
#
# @TEST-EXEC-FAIL: zeek -b ./does_not_exist.zeek 2>err
# @TEST-EXEC: grep -q "failed to get canonical path" err || grep -q "can't find" err
