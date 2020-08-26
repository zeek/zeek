# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC:      TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

local x: any = 0;

switch ( x ) {
case type count as i:
	print "count", i;
	fallthrough;  # This is invalid
case type double as d:
	print "double", d;
	break;
}

switch ( x ) {
case type count as i:
	print "count", i;

	if ( i == 0 )
		fallthrough;  # This is invalid
	else
		fallthrough;  # This is invalid

	break;
case type double as d:
	print "double", d;
	break;
}

switch ( x ) {
case type count as i:
	print "count", i;

	switch ( x as count ) {
	case 0:
		fallthrough;  # This is valid (inside nested switch statement)
	case 1:
		print "1";
		break;
	}

	break;
case type double as d:
	print "double", d;
	break;
}

switch ( x as count ) {
case 0:
	print "0";
	fallthrough;
case 1:
	print "1";
	break;
}

switch ( x ) {
case type count:
	print "count";
	fallthrough;
case type double:
	print "double";
	break;
}
