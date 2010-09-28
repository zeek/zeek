#! /usr/bin/env python
#
# Use with broccoli/test/broping.bro.

from time import sleep
from broccoli import *

@event
def pong(src_time, dst_time, seq):
    print "pong event: seq=%i, time=%f/%f s" % (seq, 
        dst_time - src_time, current_time() - src_time)
             
bc = Connection("127.0.0.1:47758")

seq = 1

while True:
    bc.send("ping", time(current_time()), count(seq))

    seq += 1
    sleep(1)
    


