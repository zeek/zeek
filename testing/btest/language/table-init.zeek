# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global global_table: table[count] of string = {
    [1] = "one",
	[2] = "two"
} &default = "global table default";

event zeek_init()
    {
    local local_table: table[count] of string = {
         [3] = "three",
		 [4] = "four"
    } &default = "local table default";

    print global_table;
    print global_table[0];
    print local_table;
    print local_table[0];
    }
