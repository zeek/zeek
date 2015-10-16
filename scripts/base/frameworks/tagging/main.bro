##! This module is for tagging networks and hosts with
##! arbitrary strings and an API for retrieving tags 
##! for IP addresses.

@load base/utils/addrs
@load base/frameworks/cluster

module Tagging;

export {
	## Define your filename (on disk) of host tags with this.
	const tag_file = "" &redef;

	## The function to grab tags.
	global get: function(host: addr): set[string];

	## The tags stored in memory. 
	global tags: table[subnet] of set[string] = {};

	## An event to indicate that reading the tagging file 
	## from disk is complete.
	global read_done: event();
}

type Tag: record {
	host: string;
	tag: string;
};

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "tagging" )
		{
		event Tagging::read_done();
		}
	}

event Tagging::read_entry(desc: Input::EventDescription, tpe: Input::Event, tag: Tagging::Tag)
	{
	local n: subnet = [::]/0;
	if ( is_valid_ip(tag$host) )
		{
		local a = to_addr(tag$host);
		local ext = "";
		if ( is_v6_addr(a) )
			ext = "/128";
		else 
			ext = "/32";

		n = to_subnet(tag$host + ext);
		}
	else
		{
		n = to_subnet(tag$host);
		# Do a reporter message if this fails.
		}
	
	# Use the subnet null indicator value.
	if ( n != [::]/0 )
		{
		# We iterate over the set here
		# because checking for a subnet in a set
		# of subnets will do longest prefix matching 
		# which can screw up adding an empty set for
		# a subnet and cause some subnets to not make 
		# it into the tags table.
		local found_net = F;
		for ( tmp_n in tags )
			{
			if ( tmp_n == n )
				found_net = T;
			}
		if ( !found_net )
			tags[n] = set();

		add tags[n][tag$tag];
		}
	}

event bro_init() &priority=5
	{
	if ( ! Cluster::is_enabled() ||
	     Cluster::local_node_type() == Cluster::MANAGER )
		{
		if ( tag_file != "" )
			{
			Input::add_event([$source=tag_file,
			                  $reader=Input::READER_ASCII,
			                  $mode=Input::REREAD,
			                  $name="tagging",
			                  $fields=Tagging::Tag,
			                  $ev=Tagging::read_entry]);
			}
		}
	}

function get(host: addr): set[string]
	{
	local output_values: set[string] = set();
	if ( host in tags )
		{
		for ( sn in tags )
			{
			if ( host in sn )
				{
				for ( tag in tags[sn] )
					{
					if ( host in sn && tag != "" )
						{
						add output_values[tag];
						}
					}
				}
			}
		}

	return output_values;
	}
