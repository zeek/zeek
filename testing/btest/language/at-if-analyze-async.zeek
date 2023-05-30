# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

module Squarer;

export {
	global async_square: function(c: count): count;
}

@if ( T ) &analyze
function async_square(c: count): count {
	return when [c] ( T ) {
		return c * c;
	}
}

@else
function async_square(c: count): count {
	return when [c] ( T ) {
		return c * c;
	}
}
@endif
