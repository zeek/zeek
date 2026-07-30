# @TEST-DOC: Regression test for #2289 from vpax - previously this printed "There's way this should happen", now it's a syntax error.
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff-remove-abspath .stderr

event zeek_init()
	{
@if ( T )
	if ( F )
@else
	if ( F )
@endif
		print "There's no way this should happen";
	}
