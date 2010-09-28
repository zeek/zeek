
@load listen-clear
redef listen_port_clear    = 47758/tcp;

redef Remote::destinations += {
	["broping"] = [$host = 127.0.0.1, $events = /test1|test3/, $connect=F, $ssl=F]
};


### Testing atomic types.

type foo: enum { CONST1, CONST2, CONST3 };

# No enum currently as Broccoli has trouble receiving them.
global test2: event(a: int, b: count, c: time, d: interval, e: bool, f: double, g: string, h: port, i: addr, j: net, k: subnet);
global test2b: event(a: int, b: count, c: time, d: interval, e: bool, f: double, g: string, h: port, i: addr, j: net, k: subnet);

event test1(a: int, b: count, c: time, d: interval, e: bool, f: double, g: string, h: port, i: addr, j: net, k: subnet)
{
    print "==== atomic";
    print a;
    print b;
    print c;
    print d;
    print e;
    print f;
    print g;
    print h;
    print i;
    print j;
    print k;
    
    event test2(-4, 42, current_time(), 1min, T, 3.14, "Hurz", 12345/udp, 1.2.3.4, 10.0., 22.33.44.0/24);
    event test2(a,b,c,d,e,f,g,h,i,j,k);
    event test2b(a,b,c,d,e,f,g,h,i,j,k);
}

### Testing record types.

type rec: record {
    a: int;
    b: addr;
};

global test4: event(r: rec);

event test3(r: rec)
{
    print "==== record";
    print r$a, r$b;
    event test4(r);
    
    local r2 : rec;
    r2$a = 99;
    r2$b = 3.4.5.1;
    event test4(r2);
}
