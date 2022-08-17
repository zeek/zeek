# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout

; # This is required - I have not understood it.

@if ( T )
print "yes";
@endif

@if ( F )
print "no";
@else
print "yes";
@endif
