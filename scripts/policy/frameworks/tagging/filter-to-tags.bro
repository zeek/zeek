##! Filter monitored traffic to only include hosts and
##! networks 

@load base/frameworks/tagging
@load base/frameworks/packet-filter

module Tagging;

export {
	## The set of strings (tags) to filter traffic to.
	global monitored_tags: set[string] = {} &redef;
}

event Tag::read_done()
	{
	local networks_bpf = "";
	for ( network in Tagging::tags )
		{
		networks_bpf = PacketFilter::combine_filters(networks_bpf,
		                                             "or",
		                                             fmt("net %s", network)); 
		}

	capture_filters["tag-filter"] = networks_bpf;
	PacketFilter::install();
	}