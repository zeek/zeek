# @TEST-EXEC: zeek -b %INPUT mynum=0 mytable='{["one"] = "1"}' mystr="" MyMod::str="Good" >1.out
# @TEST-EXEC: zeek -b %INPUT mynum=0 mytable+='{["one"] = "1"}' >2.out

# @TEST-EXEC-FAIL: zeek -b %INPUT no_such_var=13 >3.out 2>&1
# @TEST-EXEC-FAIL: zeek -b %INPUT mynum="" mytable="" >4.out 2>&1

# @TEST-EXEC: btest-diff 1.out
# @TEST-EXEC: btest-diff 2.out
# @TEST-EXEC: btest-diff 3.out
# @TEST-EXEC: btest-diff 4.out

const mynum: count &redef;
const mytable: table[string] of string = {["zero"] = "0"} &redef;
option mystr="default";

module MyMod;
export { option str="def"; }
module GLOBAL;

event zeek_init()
	{
	print "mystr", mystr;
	print "mynum", mynum;
	print "mytable", to_json(mytable);
	print "MyMod::str", MyMod::str;
	}

