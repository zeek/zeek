# $Id: broctl.bro 6811 2009-07-06 20:41:10Z robin $
#
# Data structures to define the three types of nodes (workers, proxies, and manager).

const BROCTL = T;

const WORKER = to_count(getenv("BRO_WORKER")) &redef;
const PROXY = to_count(getenv("BRO_PROXY")) &redef;
const MANAGER = to_count(getenv("BRO_MANAGER")) &redef;
const STANDALONE = to_count(getenv("BRO_STANDALONE")) &redef;

const env_var_missing = (WORKER == 0 && PROXY == 0 && MANAGER == 0 && STANDALONE == 0);

# Make sure we have some reasonable values because these are actually
# used before we get a chance to abort.
redef WORKER = WORKER > 0 ? WORKER : 1;
redef PROXY = PROXY > 0 ? PROXY : 1;
redef MANAGER = MANAGER > 0 ? MANAGER : 1;

@load cluster-by-addrs
@load remote-update
@load checkpoint 

# FIXME: Load them here to work around a namespace bug.
@load conn
@load port-name
	
module BroCtl;

export {
	# Events which are sent by the broctl when dynamically connecting to a
	# running instance. 
	const update_events = /.*(configuration_update|request_id|get_peer_status|get_net_stats).*/;

    # The following options are configured from broctl-layout.bro.

	# Directory where broctl is archiving logs. 
	const log_dir = "/not/set" &redef;

	# Host where TM is running or 0.0.0.0 if none. 
	const tm_host = 0.0.0.0 &redef;

	# Host where TM is running or 0.0.0.0 if none. 
	const tm_port = 47757/tcp &redef;

}

# PROXY record.
type pnode: record {
	ip: addr;                       
	p: port;                        
	tag: string;
};

# WORKER record.
type snode: record {
    ip: addr;                       
	p: port;                        
	interface: string &optional;    
	proxy: pnode;                   # proxy ip this worker uses
	tag: string;
};

# MANAGER record.
type mnode: record {
    ip: addr;                       
	p: port;                        
	tag: string;
};

export {
	global manager: mnode &redef;
    global proxies: table[count] of pnode &redef;
    global workers: table[count] of snode &redef;
}

@load broctl-layout
	
event bro_init()
	{
	if ( env_var_missing )
		{
		print "None of the broctl environment variables BRO_{MANAGER,WORKER,PROXY} set, aborting.";
		terminate();
		}
	
	local descr = open(".peer_description");
	print descr, peer_description;
	}

@load broctl-events

# Change some defaults.
	
redef enable_syslog = F;
redef check_for_unused_event_handlers = F;
