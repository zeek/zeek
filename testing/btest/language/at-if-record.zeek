# @TEST-DOC: Test that @if conditionals are allowed within record definitions.
#
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT common.zeek
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stderr

type r: record {
  c: count;
@if ( T )
  d: double;
@endif
};

# @TEST-START-NEXT
type r: record {
  c: count;
@if ( T )
  d: double;
  s: string;
@endif
};

# @TEST-START-NEXT
type r: record {
  c: count;
@if ( F )
  d: double;
@else
  s: string;
@endif
};

# @TEST-START-NEXT
type r: record {
  c: count;
@if ( F )
  d: double;
@else
  s: string;
@endif
  z: addr;
};

# @TEST-START-NEXT
type r: record {};

redef record r += {
  c: count &default=0;
@if ( T )
  d: double &default=0.0;
@endif
};

# @TEST-START-NEXT
# Pretty strange usage.
@if ( T )
type r: record {
  c: count;
@endif
  d: double;
};

# @TEST-START-NEXT
# Even more strange.
@if ( T )
type r: record {
  c: count;
@endif

@if ( F )
  d: double &default=1.0;;
};
@else
  d: double &default=42.0;
};
@endif


# @TEST-START-FILE common.zeek
event zeek_init()
	{
	print "r", record_fields(r);
	}
# @TEST-END-FILE
