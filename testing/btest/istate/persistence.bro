#
# @TEST-EXEC: bro -r $TRACES/empty.trace write.bro %INPUT 
# @TEST-EXEC: cp vars.log vars.write.log
# @TEST-EXEC: bro read.bro %INPUT 
# @TEST-EXEC: cp vars.log vars.read.log
# @TEST-EXEC: btest-diff vars.read.log
# @TEST-EXEC: btest-diff vars.write.log
# @TEST-EXEC: cmp vars.read.log vars.write.log

### Common code for reader and writer.

event bro_done()
	{
	local out = open("vars.log");
	print out, foo1;
	print out, foo2;
	print out, foo3;
	print out, foo4;
	print out, foo5;
	print out, foo6;
	print out, foo8;
	print out, foo9;
	print out, foo10;
	print out, foo11;
	print out, foo12;
	print out, foo13;
	print out, foo14;
	print out, foo15;
	print out, foo16;
	print out, foo17;
	}

	
	
	

@TEST-START-FILE read.bro

global foo1: count &persistent &synchronized;
global foo2: int &persistent &synchronized;
global foo3: string &persistent &synchronized; 
global foo4: addr &persistent &synchronized; 
global foo5: subnet &persistent &synchronized; 
global foo6: double &persistent &synchronized; 
global foo8: interval &persistent &synchronized; 
global foo9: table[count] of string &persistent &synchronized;
global foo10: file &persistent &synchronized; 
global foo11: pattern &persistent &synchronized; 
global foo12: set[count] &persistent &synchronized; 
global foo13: table[count, string] of count &persistent &synchronized;
global foo14: table[count] of pattern &persistent &synchronized;
global foo15: port &persistent &synchronized;
global foo16: vector of count &persistent &synchronized;

type type1: record {
    a: string;
    b: count &default=42;
    c: double &optional;
    };

type type2: record {
    a: string;
    b: type1;
    c: type1;
    d: double;
    };

global foo17: type2  &persistent &synchronized;

@TEST-END-FILE

@TEST-START-FILE write.bro

global foo1 = 42 &persistent &synchronized;
global foo2 = -42 &persistent &synchronized;
global foo3 = "Hallihallo" &persistent &synchronized; 
global foo4 = 1.2.3.4 &persistent &synchronized; 
global foo5 = 1.2.0.0/16 &persistent &synchronized; 
global foo6 = 3.14 &persistent &synchronized; 
global foo8 = 42 secs &persistent &synchronized; 
global foo9 = { [1] = "qwerty", [2] = "uiop" } &persistent &synchronized;
global foo10 = open("test") &persistent &synchronized; 
global foo11 = /12345/ &persistent &synchronized; 
global foo12 = { 1,2,3,4,5 } &persistent &synchronized; 
global foo13  =  { [1,"ABC"] = 101, [2,"DEF"] = 102, [3,"GHI"] = 103 } &persistent &synchronized;
global foo14  =  { [12345] = foo11, [12346] = foo11 } &persistent &synchronized;
global foo15 = 42/udp &persistent &synchronized;
global foo16: vector of count = [1,2,3] &persistent &synchronized;
 
type type1: record {
    a: string;
    b: count &default=42;
    c: double &optional;
    };

type type2: record {
    a: string;
    b: type1;
    c: type1;
    d: double;
    };

global foo17: type2 = [
	$a = "yuyuyu",
    $b = [$a="rec1", $b=100, $c=1.24],
    $c = [$a="rec2", $b=200, $c=2.24],
   	$d = 7.77				   
	] &persistent &synchronized;

@TEST-END-FILE
