# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

global params: sw_params = [ $min_strlen = 2, $sw_variant = 0 ];

global min: vector of count;
global mode: vector of count;
global c: count = 0;

# Alignment pairs:
global s1: string_vec;
global s2: string_vec;

# Single alignment, no matches:
s1[++c] = "abcdefgh";
s2[c] = "ijklmnop";
min[c] = 2;;
mode[c] = 0;

# Simple single match, beginning:
s1[++c] = "AAAabcefghij";
s2[c] = "lmnopAAAqrst";
min[c] = 2;;
mode[c] = 0;

# Simple single match, middle:
s1[++c] = "abcAAAefghij";
s2[c] = "lmnopAAAqrst";
min[c] = 2;;
mode[c] = 0;

# Simple single match, end:
s1[++c] = "abcefghijAAA";
s2[c] = "lmnopAAAqrst";
min[c] = 2;;
mode[c] = 0;

# Repeated alignment:
s1[++c] = "xxxAAAyyy";
s2[c] = "AAAaAAAbAAA";
min[c] = 2;;
mode[c] = 1;

# Repeated alignment, swapped input:
s1[++c] = "AAAaAAAbAAA";
s2[c] = "xxxAAAyyy";
min[c] = 2;;
mode[c] = 1;

# Repeated alignment, split:
s1[++c] = "xxCDyABzCDyABzz";
s2[c] = "ABCD";
min[c] = 2;;
mode[c] = 1;

# Repeated alignment, split, swapped:
s1[++c] = "ABCD";
s2[c] = "xxCDyABzCDyABzz";
min[c] = 2;;
mode[c] = 1;

# Used to cause problems
s1[++c] = "Cache-control: no-cache^M^JAccept:";
s2[c] = "Accept-: deflate^M^JAccept-: Accept-";
min[c] = 6;
mode[c] = 1;

# Repeated occurrences in shorter string
s1[++c] = "xxAAxxAAxx";
s2[c]   = "yyyyyAAyyyyy";
min[c] = 2;
mode[c] = 1;

for ( i in s1 )
	{
	local ss: sw_substring_vec;

	params$min_strlen = min[i];
	params$sw_variant = mode[i];
	ss = str_smith_waterman(s1[i], s2[i], params);

	print fmt("%s - %s:", s1[i], s2[i]);

	for ( j in ss )
		print fmt("tok %d: %s (%d/%d, %s)",
				j, ss[j]$str, ss[j]$aligns[1]$index,
				ss[j]$aligns[2]$index, ss[j]$new);
	}
