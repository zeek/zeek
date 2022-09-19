# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff --binary test.txt

global cmds = "print \"hello world\";";
cmds = string_cat(cmds, "\nprint \"foobar\";");

# If we're using generated C++, turn that off for the pipe execution,
# as otherwise we'll get a complaint that there's no corresponding
# C++ bodies found for that zeek instance.
if ( piped_exec("unset ZEEK_USE_CPP; zeek", cmds) != T )
	exit(1);

# Test null output.
if ( piped_exec("cat > test.txt", "\x00\x00hello\x00\x00") != T )
	exit(1);

print "success!";
