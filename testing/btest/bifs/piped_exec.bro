# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff test.txt


global cmds = "print \"hello world\";";
cmds = string_cat(cmds, "\nprint \"foobar\";");
piped_exec("bro", cmds);

# Test null output.
piped_exec("cat > test.txt", "\x00\x00hello\x00\x00");

