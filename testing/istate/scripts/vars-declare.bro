# $Id: vars-declare.bro,v 1.1.2.2 2005/10/11 21:15:05 sommer Exp $
#
# Declares variables.

global foo1: count &persistent &synchronized;
global foo2: int &persistent &synchronized;
global foo3: string &persistent &synchronized; 
global foo4: addr &persistent &synchronized; 
global foo5: subnet &persistent &synchronized; 
global foo6: double &persistent &synchronized; 
global foo7: net &persistent &synchronized; 
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

