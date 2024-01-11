# @TEST-DOC: Regression test for past ZAM issues with for-loop table "choose".
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	local v = table([1] = 4, [2] = 12);
	for ( i1, i2 in v )
		break;

	print i1, i2;
	}
