# @TEST-EXEC-FAIL: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

redef enum nonexistent += {
	This_Causes_a_Segfault
};
