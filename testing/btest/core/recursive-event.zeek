# @TEST-EXEC: zeek %INPUT 2>&1 | grep -v termination | sort | uniq | wc -l | awk '{print $1}' >output
# @TEST-EXEC: btest-diff output

# In old version, the event would keep triggering endlessely, with the network
# time not moving forward and Bro not terminating. 
# 
# Note that the output will not be 20 because we still execute two rounds
# of events every time we drain and also at startup several (currently 3)
# rounds of events drain with the same network_time.

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

event zeek_init()
        {
        event test();
        }
