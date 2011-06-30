# $Id: large-conns.bro 1332 2005-09-07 17:39:17Z vern $

# Written by Chema Gonzalez.


# Estimates the size of large "flows" (i.e., each direction of a TCP
# connection) by noting when their sequence numbers cross a set of regions
# in the sequence space.  This can be done using a static packet filter,
# so is very efficient.  It works for (TCP) traffic that Bro otherwise doesn't
# see.

# Usage
#
# 1) Set the appropriate number_of_regions and region_size:
#
#    Modify the number_of_regions and (perhaps) region_size global
#    variables.  You do this *prior* to loading this script, so
#    for example:
#
#	const number_of_regions = 32;
#	@load large-conns
#
#    You do *not* redef them like you would with other script variables
#    (this is because they need to be used directly in the initializations
#    of other variables used by this script).
#
#    Note that number_of_regions affects the granularity
#    and definition of the script (see below).
#
# 2) To get an estimate of the true size of a flow, call:
#
#	function estimate_flow_size_and_remove(cid: conn_id, orig: bool):
#								flow_size_est
#
#    If orig=T, then an estimate of the size of the forward (originator)
#    direction is returned.  If orig=F, then the reverse (responder)
#    direction is returned.  In both cases, what's returned is a
#    flow_size_est, which includes a flag indicating whether there was
#    any estimate formed, and, if the flag is T, a lower bound, an upper bound,
#    and an inconsistency-count (which, if > 0, means that the estimates
#    came from sequence numbers that were inconsistent, and thus something
#    is wrong - perhaps packet drops by the secondary filter).  Finally,
#    calling this function causes the flow's record to be deleted.  Perhaps
#    at some point we'll need to add a version that just retrieves the
#    estimate.

type flow_size_est: record {
	have_est: bool;
	lower: double &optional;
	upper: double &optional;
	num_inconsistent: count &optional;
};

global estimate_flow_size_and_remove:
	function(cid: conn_id, orig: bool): flow_size_est;

module LargeConn;


# Rationale
#
# One of the mechanisms that Bro uses to detect large TCP flows is 
# to calculate the difference in the sequence number (seq) field contents 
# between the last packet (FIN or RST) and the first packet (SYN). This 
# method may be wrong if a) the seq number is busted (which can happen
# frequently with RST termination), or b) the seq number wraps around
# the 4GB sequence number space (note that this is OK for TCP while
# there is no ambiguity on what a packet's sequence number means,
# due to its use of a window <= 2 GB in size).
#
# The purpose of this script is to resolve these ambiguities. In other 
# words, help with differentiating truly large flows from flows with
# a busted seq, and detecting very large flows that wrap around the
# 4GB seq space. 
#
# To do so, large-flow listens to a small group of thin regions in
# the sequence space, located at equal distances from each other. The idea 
# is that a truly large flow will pass through the regions in 
# an orderly fashion, maybe several times. This script keeps track of 
# all packets that pass through any of the regions, counting the number 
# of times a packet from a given flow passes through consecutive regions. 
#
# Note that the exact number of regions, and the size of each region, can 
# be controlled by redefining the global variables number_of_regions 
# and region_size, respectively.  Both should be powers of two (if not,
# they are rounded to be such), and default to 4 and 16KB, respectively. 
# The effect of varying these parameters is the following:
#
# - Increasing number_of_regions will increase the granularity of the 
#   script, at the cost of elevating its cost in both processing (more 
#   packets will be seen) and memory (more flows will be seen). 
#   The granularity of the script is defined as the minimum variation 
#   in size the script can see. Its value is: 
#
#     granularity = (4GB / number_of_regions)
#
#   For example, if we're using 4 regions, the minimum flow size difference
#   that the script can see is 1GB.
#
#   number_of_regions also affects the script definition, defined as the 
#   smallest size of a flow which ensures that the flow will be seen by
#   the script. The script definition is:
#
#     definition = (2 * granularity)
#
#   The script sees no flow smaller than the granularity, some flows with
#   size between granularity and definition, and all flows larger than
#   definition. In our example, the script definition is 2GB (it will see
#   for sure only flows bigger than 2GB). 
#
# - Increasing region_size will only increase the resilience of the script 
#   to lost packets, at the cost of augmenting the cost in both processing 
#   and memory (see above). The default value of 16 KB is chosen to work
#   in the presence of largish packets without too much additional work.

# Set up defaults, unless the user has already specified these.  Note that
# these variables are *not* redef'able, since they are used in initializations
# later in this script (so a redef wouldn't be "seen" in time).
@ifndef ( number_of_regions )
	const number_of_regions = 4;
@endif
@ifndef ( region_size )
	const region_size = 16 * 1024;	# 16 KB
@endif


# Track the regions visited for each flow.
type t_info: record {
	last_region: count;	# last region visited
	num_regions: count;	# number of regions visited
	num_inconsistent: count;	# num. inconsistent region crossings
};

# The state expiration for this table needs to be generous, as it's
# for tracking very large flows, which could be quite long-lived.
global flow_region_info: table[conn_id] of t_info &write_expire = 6 hr;


# Returns the integer logarithm in base b.
function logarithm(base: count, x: count): count
	{
	if ( x < base )
		return 0;
	else
		return 1 + logarithm(base, x / base);
	}


# Function used to get around Bro's lack of real ordered loop.
function do_while(i: count, max: count, total: count,
			f: function(i: count, total: count): count): count
	{
	if ( i >= max )
		return total;
	else
		return do_while(++i, max, f(--i, total), f);
	}

function fn_mask_location(i: count, total: count): count
	{
	return total * 2 + 1;
	}

function fn_filter_location(i: count, total: count): count
	{
	# The location pattern is 1010101010...
	return total * 2 + (i % 2 == 0 ? 1 : 0);
	}

function fn_common_region_size(i: count, total: count): count
	{
	return total * 2;
	}


function get_interregion_distance(number_of_regions: count,
					region_size: count): count
	{
	local bits_number_of_regions = logarithm(2, number_of_regions);
	local bits_other = int_to_count(32 - bits_number_of_regions);

	return do_while(0, bits_other, 1, fn_common_region_size);
	}


global interregion_distance =
	get_interregion_distance(number_of_regions, region_size);


# Returns an estiamte of size of the flow (one direction of a TCP connection)
# that this script has seen. This is based on the number of consecutive
# regions a flow has visited, weighted with the distance between regions.  
#
# We know that the full sequence number space accounts for 4GB. This 
# space comprises number_of_regions regions, separated from each other 
# a (4GB / number_of_regions) distance. If a flow has been seen 
# in X consecutive regions, it means that the size of the flow is 
# greater than ((X - 1) * distance_between_regions) GB. 
#
# Note that seeing a flow in just one region is no different from 
# not seeing it at all. 
function estimate_flow_size_and_remove(cid: conn_id, orig: bool): flow_size_est
	{
	local id = orig ? cid :
			  [$orig_h = cid$resp_h, $orig_p = cid$resp_p,
			   $resp_h = cid$orig_h, $resp_p = cid$orig_p];

	if ( id !in flow_region_info )
		return [$have_est = F];

	local regions_crossed =
		int_to_count(flow_region_info[id]$num_regions - 1);

	local lower = regions_crossed * interregion_distance * 1.0;
	local upper = lower + interregion_distance * 2.0;
	local num_inconsis = flow_region_info[id]$num_inconsistent;

	delete flow_region_info[id];

	return [$have_est = T, $lower = lower, $upper = upper,
		$num_inconsistent = num_inconsis];
	}


# Returns a tcpdump filter corresponding to the number of regions and 
# region size requested by the user.
#
# How to calculate the tcpdump filter used to hook packet_event to the 
# secondary filter system?  We are interested only in TCP packets whose
# seq number belongs to any of the test slices. Let's focus on the case
# of 4 regions, 16KB per region.
#
# The mask should be: [ x x  L L L ... L L L  x x ... x ]
#                      <---><---------------><--------->
#                       |          |            |
#                       |          |            +-> suffix: region size
#                       |          +-> location: remaining bits
#                       +-> prefix: number of equidistant regions
#
# The 32-bit seq number is masked as follows: 
#
#   - suffix: defines size of the regions (16KB implies log_2(16KB) = 14 bits)
#
#   - location: defines the exact location of the 4 regions. Note that, to 
#     minimize the amount of data we keep, the location will be distinct from
#     zero, so segments with seq == 0 are not in a valid region
#
#   - prefix: defines number of regions (4 implies log_2(4) = 2 bits)
#
# E.g., the mask will be seq_number & 0011...1100..00_2 = 00LL..LL00..00_2,
# which, by setting the location to 1010101010101010, will finally be
# seq_number & 0011...1100..00_2 = 00101010101010101000..00_2, i.e., 
# seq_number & 0x3fffc000 = 0x2aaa8000. 
#
# For that particular parameterization, we'd like to wind up with a
# packet event filter of "(tcp[4:4] & 0x3fffc000) == 0x2aaa8000".

function get_event_filter(number_of_regions: count, region_size: count): string
	{
	local bits_number_of_regions = logarithm(2, number_of_regions);
	local bits_region_size = logarithm(2, region_size);
	local bits_remaining = 
		int_to_count(32 - bits_number_of_regions - bits_region_size);

	# Set the bits corresponding to the location:
	#	i = 0;
	#	while ( i < bits_remaining )
	#		{
	#		mask = (mask * 2) + 1;
	#		filter = (filter * 2) + (((i % 2) == 0) ? 1 : 0);
	#		++i;
	#		}
	local mask = do_while(0, bits_remaining, 0, fn_mask_location);
	local filter = do_while(0, bits_remaining, 0, fn_filter_location);

	# Set the bits corrsponding to the region size
	#	i = 0;
	#	while ( i < bits_region_size )
	#		{
	#		mask = mask * 2;
	#		filter = filter * 2;
	#		++i;
	#		}
	mask = do_while(0, bits_region_size, mask, fn_common_region_size);
	filter = do_while(0, bits_region_size, filter, fn_common_region_size);

	return fmt("(tcp[4:4] & 0x%x) == 0x%x", mask, filter);
	}


# packet_event --
#
# This event is raised once per (TCP) packet falling into any of the regions. 
# It updates the flow_region_info table. 
event packet_event(filter: string, pkt: pkt_hdr)
	{
	# Distill the region from the seq number.
	local region = pkt$tcp$seq / interregion_distance;

	# Get packet info and update global counters.
	local cid = [$orig_h = pkt$ip$src, $orig_p = pkt$tcp$sport,
			$resp_h = pkt$ip$dst, $resp_p = pkt$tcp$dport];

	if ( cid !in flow_region_info )
		{
		flow_region_info[cid] =
			[$last_region = region, $num_regions = 1,
			 $num_inconsistent = 0];
		return;
		}

	local info = flow_region_info[cid];
	local next_region = (info$last_region + 1) % number_of_regions;

	if ( region == next_region )
		{ # flow seen in the next region
		info$last_region = region;
		++info$num_regions;
		}

	else if ( region == info$last_region )
		{ # flow seen in the same region, ignore
		}
	else 
		{
		# Flow seen in another region (not the next one).
		info$last_region = region;
		info$num_regions = 1;	# restart accounting
		++info$num_inconsistent;
		}
	}


# Glue the filter into the secondary filter hookup.
global packet_event_filter = get_event_filter(number_of_regions, region_size);
redef secondary_filters += { [packet_event_filter] = packet_event };
