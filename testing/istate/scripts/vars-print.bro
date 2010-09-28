# $Id: vars-print.bro,v 1.1.2.2 2005/10/11 21:15:05 sommer Exp $
#
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
	print out, foo7;
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

	
	
	
