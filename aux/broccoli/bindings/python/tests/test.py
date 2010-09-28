#! /usr/bin/env python

import time as Time

from broccoli import *

@event
def test2(a,b,c,d,e,f,g,h,i,j,k):
    global recv
    recv += 1
    print "==== atomic a %d ====" % recv
    print repr(a), a
    print repr(b), b
    print repr(c), c
    print repr(d), d
    print repr(e), e
    print repr(f), f
    print repr(g), g
    print repr(h), h
    print repr(i), i
    print repr(j), j
    print repr(j), k

# Same except with typing this time.    
@event(int,count,time,interval,bool,double,addr,port,addr,net,subnet)
def test2b(a,b,c,d,e,f,g,h,i,j,k):
    print "==== atomic b %d ====" % recv
    print repr(a), a
    print repr(b), b
    print repr(c), c
    print repr(d), d
    print repr(e), e
    print repr(f), f
    print repr(g), g
    print repr(h), h
    print repr(i), i
    print repr(j), j
    print repr(j), k
    
rec = record_type("a", "b")    
    
@event(rec)    
def test4(r):
    global recv
    recv += 1
    print "==== record %d ====" % recv
    print repr(r)
    print repr(r.a), r.a
    print repr(r.b), r.b
    
bc = Connection("127.0.0.1:47758")

bc.send("test1", 
    int(-10), 
    count(2), 
    time(current_time()), 
    interval(120), 
    bool(False), 
    double(1.5), 
    string("Servus"), 
    port("5555/tcp"), 
    addr("6.7.6.5"), 
    net("20.0."), 
    subnet("192.168.0.0/16")
    )

recv = 0
while True:
    bc.processInput();
    if recv == 2:
        break
    Time.sleep(1)

    
r = record(rec)
r.a = 42;
r.b = addr("6.6.7.7")

bc.send("test3", r)
    
recv = 0
while True:
    bc.processInput();
    if recv == 2:
        break
    Time.sleep(1)
    
    

