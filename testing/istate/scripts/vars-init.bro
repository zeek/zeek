# $Id: vars-init.bro,v 1.1.2.2 2005/10/11 21:15:05 sommer Exp $
# 
# Instantiates variables.

global foo1 = 42 &persistent &synchronized;
global foo2 = -42 &persistent &synchronized;
global foo3 = "Hallihallo" &persistent &synchronized; 
global foo4 = 1.2.3.4 &persistent &synchronized; 
global foo5 = 1.2.0.0/16 &persistent &synchronized; 
global foo6 = 3.14 &persistent &synchronized; 
global foo7 = 131.159. &persistent &synchronized; 
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


