# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run sender   bro -b %INPUT ../sender.bro
# @TEST-EXEC: btest-bg-run receiver bro -b %INPUT ../receiver.bro
# @TEST-EXEC: btest-bg-wait 20
#
# @TEST-EXEC: btest-diff sender/vars.log
# @TEST-EXEC: btest-diff receiver/vars.log
# @TEST-EXEC: cmp sender/vars.log receiver/vars.log

### Common code for sender and receiver.

# Instantiate variables.

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
global foo18: count &persistent &synchronized;  # not initialized
 
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
    e: double &optional;
    };

global foo17: type2 = [
	$a = "yuyuyu",
	$b = [$a="rec1", $b=100, $c=1.24],
	$c = [$a="rec2", $b=200, $c=2.24],
	$d = 7.77, $e=100.0
	] &persistent &synchronized;

# Print variables.

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
	print out, foo18;
	}


@TEST-START-FILE sender.bro

# Perform modifications on variables.

function modify()
	{
	foo1 = 420;
	++foo1;
	
	--foo2;
	
	foo3 = "Jodel";
	
	foo4 = 4.3.2.1; 
	
	foo5 = 4.0.0.0/8; 
	
	foo6 = 21;
	
	foo9[3] = "asdfg1";
	foo9[1] = "asdfg2";
	delete foo9[2];
	
	foo10 = open("test2");
	
	foo11 = /abbcdefgh/;
	
	add foo12[6];
	delete foo12[1];
	
	foo13[4,"JKL"] = 104;
	delete foo13[1,"ABC"];
	++foo13[2,"DEF"];
	
	foo14[6767] = /QWERTZ/;
	
	foo15 = 6667/tcp;
	
	foo16[3] = 4;
	foo16[1] = 20;
	++foo16[0];
	
	local x: type1;
	x$a = "pop";
	++x$b;
	x$c = 9.999;
	foo17$a = "zxzxzx";
	foo17$b = x;
	foo17$c$a = "IOIOI";
	++foo17$c$b;
	foo17$c$c = 612.2;
	foo17$d = 6.6666;
	delete foo17$e;
	
	foo2 = 1234567;
	foo18 = 122112;
	}

@load frameworks/communication/listen

event remote_connection_handshake_done(p: event_peer)
	{
	modify();
	terminate_communication();
	}
			 
redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $sync=T]
};

@TEST-END-FILE

#############

@TEST-START-FILE receiver.bro

@load base/frameworks/communication

event bro_init()
    {
    capture_events("events.bst");
    }
	
redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $events = /.*/, $connect=T, $sync=T,
               $retry=1sec]
};

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

@TEST-END-FILE
