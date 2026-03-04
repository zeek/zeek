# This test verifies Zeek's file path normalization.
#
# Absolute paths are preserved but normalized.
# cygpath converts the POSIX $PWD (e.g. /c/projects/...) to a Windows-style
# path (e.g. C:/projects/...) so the sed substitution matches Zeek's output
# on Windows. On other platforms cygpath is absent and the fallback uses $PWD.
# @TEST-EXEC: zeek -b $PWD/././test.zeek 2>&1 | sed "s|$(cygpath -m "$PWD" 2>/dev/null || echo "$PWD")|/...|;s|$PWD|/...|" >output
#
# Unanchored files become localized ("./test.zeek"):
# @TEST-EXEC: zeek -b test.zeek 2>>output
#
# Redundant path constructs get stripped:
# @TEST-EXEC: zeek -b .//test.zeek 2>>output
# @TEST-EXEC: zeek -b ././test.zeek 2>>output
#
# More complex constructs get normalized too:
# @TEST-EXEC: mkdir foo
# @TEST-EXEC: zeek -b ./foo/../././test.zeek 2>>output
#
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE test.zeek
event idontexist() { }
# @TEST-END-FILE
