# $Id: vars-modify.bro,v 1.1.2.2 2005/10/11 21:15:05 sommer Exp $
#
# Performs modifications on variables.

function modify()
	{
	foo1 = 420;
	++foo1;
	
	--foo2;
	
	foo3 = "Jodel";
	
	foo4 = 4.3.2.1; 
	
	foo5 = 4.0.0.0/8; 
	
	foo6 = 21;
	
	foo7 = 192.150.186; 
	
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
	
	foo16[4] = 4;
	foo16[2] = 20;
	++foo16[1];
	
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
	
	foo2 = 1234567;
	}




