# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff test.txt


global cmds = "print \"hello world\";";
cmds = string_cat(cmds, "\nprint \"foobar\";");
if ( piped_exec("zeek", cmds) != T )
	exit(1);

# Test null output.
if ( piped_exec("cat > test.txt", "\x00\x00hello\x00\x00") != T )
	exit(1);

