#! /usr/bin/env python
#
# Use with broccoli/test/broping-record.bro.

from time import sleep
from broccoli import *

ping_data = record_type("seq", "src_time")
pong_data = record_type("seq", "src_time", "dst_time")

@event(pong_data)
def pong(data):
    print "pong event: seq=%i, time=%f/%f s" % (data.seq, 
        data.dst_time - data.src_time, current_time() - data.src_time)

bc = Connection("127.0.0.1:47758")

seq = 1

while True:
    data = record(ping_data)
    data.seq = count(seq)
    data.src_time = time(current_time())
    bc.send("ping", data)
    
    seq += 1
    sleep(1)
    


