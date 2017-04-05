# @TEST-EXEC: bro %INPUT 2>&1 | grep -v termination | sort | uniq | wc -l | awk '{print $1}' >output
# @TEST-EXEC: btest-diff output

# In old version, the event would keep triggering endlessely, with the network
# time not moving forward and Bro not terminating. 
# 
# Note that the output will be 10 (not 20) because we still execute two rounds
# of events every time we drain.

# In the CAF runloop, this is currently 9 because the first cycle of the run
# loop will process the threading manager and, like the old version, time does not
# advance if a non-packet IOSource gets processed during that loop cycle.
# In the old version, threading is ignored since there's no threads yet added.

redef exit_only_after_terminate=T;

global c = 0;

event test()
        {
	c += 1;

	if ( c == 20 ) 
		{
		terminate();
		return;
		}
	
        print network_time();
        event test();
        }

event bro_init()
        {
        event test();
        }
