# @TEST-DOC: Regression tests for past ZAM bugs handling empty infinite loops
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC-FAIL: zeek -b -O ZAM %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

event zeek_init()
	{
	# It used to be that ZAM would fault doing control-flow propagation
	# when compiling empty infinite loops. Now it should generate a
	# compile-time error.
	while ( T )
		;
	}
