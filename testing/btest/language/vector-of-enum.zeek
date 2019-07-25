# @TEST-EXEC: zeek %INPUT

# This regression test checks a special case in the vector code.
# Test succeeds if it doesn't crash Zeek.
# (Error was "internal error in <stdin>, line 2: bad type in merge_types()")

type color : enum {Red, White, Blue};
global v = vector(Red, White, Blue);
