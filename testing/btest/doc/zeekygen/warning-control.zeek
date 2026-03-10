# Test that zeekygen warnings are disabled by default and can be enabled
# with ZEEK_ENABLE_ZEEKYGEN_WARNINGS environment variable.
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; unset ZEEK_ENABLE_ZEEKYGEN_WARNINGS; zeek %INPUT > default 2>&1
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; ZEEK_ENABLE_ZEEKYGEN_WARNINGS=1 zeek %INPUT > with_warning 2>&1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff default
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff with_warning

## This is an extraneous zeekygen comment that has no identifier following it.

@load base/frameworks/notice
