# Bro shouldn't crash when doing nothing, nor outputting anything.
#
# @TEST-EXEC: cat /dev/null | zeek >output 2>&1
# @TEST-EXEC: btest-diff output
