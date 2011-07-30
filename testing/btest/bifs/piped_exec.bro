# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output

global cmds = "print \"hello world\";";
cmds = string_cat(cmds, "\nprint \"foobar\";");
piped_exec("bro", cmds);
