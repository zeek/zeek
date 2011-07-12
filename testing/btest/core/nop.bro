# Bro shouldn't crash when doing nothing, nor outputting anything.
#
# @TEST-EXEC: cat /dev/null | bro >output 2>&1
# @TEST-EXEC: btest-diff output
