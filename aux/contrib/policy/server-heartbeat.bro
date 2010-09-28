# heartbeat-server.bro
# Listen for remote heartbeat events
# $Id: server-heartbeat.bro,v 1.6 2007/02/26 07:03:20 jason Exp $

# To use this analyzer, be sure to redef Remote::destinations 
# and probably mail_dest too.

# start listening for remote hosts
@load listen-clear

# how long till 'lost' messages are genterated
global max_timeout = 30 min &redef;

# how often to bug about missing servers (60minutes)
global report_nag_time = 1 hr &redef;

# how many times to do this for? (0 forever)
global report_nag_times: count = 0 &redef;

#################################################
# shouldn't need to modifiy anything below here #
#################################################
# setup our Notice type
redef enum Notice += { LostHeartBeat } ;

global report_missing_heartbeat: 
    function(t: table[string] of count, idx: string) : interval;

global reported_address_heartbeat: table[string] of count &default=0 
    &create_expire = report_nag_time &expire_func = report_missing_heartbeat;

# function called when a monitored stream times-out
global lost_heartbeat:
        function(t: table[string] of event_peer, idx: string) : interval;

# table holding who we are monitoring (cache peer for use in notice)
global heartbeats : table[string] of event_peer &write_expire = max_timeout &expire_func = lost_heartbeat;

# send email if we expire an entry in the table
function lost_heartbeat(t: table[string] of event_peer, idx: string): interval
{
    NOTICE([$note=LostHeartBeat, $src_peer=heartbeats[idx], 
    	$msg=fmt("Lost heartbeat from %s", idx) ]);

    # pop him into the report table
    reported_address_heartbeat[idx]= report_nag_times;

    return 0 sec;
}

# send email if this server is *still* down
function report_missing_heartbeat(t: table[string] of count, idx: string): interval
{
    # if he is back, just let this entry expire
    if (idx in heartbeats)
    {
    	return 0 secs;
    }

    NOTICE([$note=LostHeartBeat, 
        $msg=fmt("Still missing heartbeat from %s", idx) ]);

    # pop him back into the report table
    local times: count;
    times = reported_address_heartbeat[idx];

    # if he has time left put him back
    if ( times > 1 ) 
        reported_address_heartbeat[idx] = times - 1;
    # if he is set to 0, keep him forever
    else if  (times == 0 )
        reported_address_heartbeat[idx] = 0;

    # not exactly sure why, but ....
    return 60 sec;
}


# update table that we recieved a msg
event heartbeat_event( ts:double, orig_h:addr, info:string )
    {
    local hb_peer = get_event_peer();
    local hb_host = fmt("%s", hb_peer$host);

    print fmt("got heartbeat from %s", orig_h) ;

    # use this one if you want to be notified if the service
    # went down and came back up on a differnt port
    #local hb_host = fmt("%s:%s", hb_peer$host, hb_peer$p);
    heartbeats[hb_host] = hb_peer;

    }
