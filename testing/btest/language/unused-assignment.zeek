# Don't run for C++ scripts, they don't do this analysis at run-time.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# Note, we don't use "zeek -b" because we want to exercise the usage machinery
# across all of the default scripts.
# @TEST-EXEC: ZEEK_USAGE_ISSUES=1 zeek %INPUT >out 2>&1
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-DOC: The "-u" flag should warn about unused assignments and &is_used suppresses it.

event zeek_init()
	{
	local please_warn = "test";
	local please_no_warning = "test" &is_used;

	local reassign = "original"; # should complain about this being unused
	reassign = "complain here too";
	reassign = "but not here";
	print reassign;
	}
