# $Id: load-level.bro 1904 2005-12-14 03:27:15Z vern $
#
# Support for shedding/reinstating load.

@load notice

# If no load_level is given, a filter is always activated.
#
# If a level is given for a filter (using the same ID than in
# {capture,restrict}_filter), then:
#
#     -  a capture_filter is activated if current load_level is <=
#     -  a restrict_filter is activated if current load_level is >=

global capture_load_levels: table[string] of PcapFilterID &redef;
global restrict_load_levels: table[string] of PcapFilterID &redef;

redef enum PcapFilterID += {
	LoadLevel1, LoadLevel2, LoadLevel3, LoadLevel4, LoadLevel5,
	LoadLevel6, LoadLevel7, LoadLevel8, LoadLevel9, LoadLevel10,
};

const Levels = {
	LoadLevel1, LoadLevel2, LoadLevel3, LoadLevel4, LoadLevel5,
	LoadLevel6, LoadLevel7, LoadLevel8, LoadLevel9, LoadLevel10
};

# The load-level cannot not leave this interval.
const MinLoad = LoadLevel1;
const MaxLoad = LoadLevel10;

# The initial load-level.
global default_load_level = LoadLevel10 &redef;

# Set to 0 to turn off any changes of the filter.
global can_adjust_filter = T &redef;

global current_load_level = DefaultPcapFilter;

global ll_file = open_log_file("load-level");

# Interface functions for switching load levels.

function set_load_level(level: PcapFilterID): bool
	{
	if ( level == current_load_level )
		return T;

	if ( ! can_adjust_filter )
		{
		print ll_file, fmt("%.6f can't set %s (load-levels are turned off)", network_time(), level);
		return F;
		}

	if ( ! install_pcap_filter(level) )
		{
		print ll_file, fmt("%.6f can't set %s (install failed)", network_time(), level);

		# Don't try again.
		can_adjust_filter = F;
		return F;
		}

	current_load_level = level;

	print ll_file, fmt("%.6f switched to %s", network_time(), level);

	return T;
	}

# Too bad that we can't use enums like integers...
const IncreaseLoadLevelTab = {
	[LoadLevel1] = LoadLevel2,
	[LoadLevel2] = LoadLevel3,
	[LoadLevel3] = LoadLevel4,
	[LoadLevel4] = LoadLevel5,
	[LoadLevel5] = LoadLevel6,
	[LoadLevel6] = LoadLevel7,
	[LoadLevel7] = LoadLevel8,
	[LoadLevel8] = LoadLevel9,
	[LoadLevel9] = LoadLevel10,
	[LoadLevel10] = LoadLevel10,
};

const DecreaseLoadLevelTab = {
	[LoadLevel1] = LoadLevel1,
	[LoadLevel2] = LoadLevel1,
	[LoadLevel3] = LoadLevel2,
	[LoadLevel4] = LoadLevel3,
	[LoadLevel5] = LoadLevel4,
	[LoadLevel6] = LoadLevel5,
	[LoadLevel7] = LoadLevel6,
	[LoadLevel8] = LoadLevel7,
	[LoadLevel9] = LoadLevel8,
	[LoadLevel10] = LoadLevel9,
};

const LoadLevelToInt = {
	[DefaultPcapFilter] = 0,
	[LoadLevel1] = 1,
	[LoadLevel2] = 2,
	[LoadLevel3] = 3,
	[LoadLevel4] = 4,
	[LoadLevel5] = 5,
	[LoadLevel6] = 6,
	[LoadLevel7] = 7,
	[LoadLevel8] = 8,
	[LoadLevel9] = 9,
	[LoadLevel10] = 10,
};

function increase_load_level()
	{
	set_load_level(IncreaseLoadLevelTab[current_load_level]);
	}

function decrease_load_level()
	{
	set_load_level(DecreaseLoadLevelTab[current_load_level]);
	}


# Internal functions.

function load_level_error()
	{
	print ll_file, fmt("%.6f Error, switching back to DefaultPcapFilter",
				network_time());

	install_default_pcap_filter();

	# Don't try changing the load level any more.
	can_adjust_filter = F;
	}

function build_load_level_filter(level: PcapFilterID): string
	{
	# Build up capture_filter.
	local cfilter = "";

	for ( id in capture_filters )
		{
		if ( id !in capture_load_levels ||
		     LoadLevelToInt[level] <= LoadLevelToInt[capture_load_levels[id]] )
			cfilter = add_to_pcap_filter(cfilter, capture_filters[id], "or");
		}

	# Build up restrict_filter.
	local rfilter = "";
	for ( id in restrict_filters )
		{
		if ( id !in restrict_load_levels ||
		     LoadLevelToInt[level] >= LoadLevelToInt[restrict_load_levels[id]] )
			rfilter = add_to_pcap_filter(rfilter, restrict_filters[id], "and");
		}

	return join_filters(cfilter, rfilter);
	}

function precompile_load_level_filters(): bool
	{
	print ll_file, fmt("%.6f <<< Begin of precompilation", network_time() );

	for ( i in Levels )
		{
		local filter = build_load_level_filter(i);

		if ( ! precompile_pcap_filter(i, filter) )
			{
			print ll_file, fmt("%.6f Level %d: %s",
				network_time(), LoadLevelToInt[i], pcap_error());
			load_level_error();
			return F;
			}

		print ll_file, fmt("%.6f  Level %2d: %s", network_time(), LoadLevelToInt[i], filter);
		}

	print ll_file, fmt("%.6f >>> End of precompilation", network_time() );

	return T;
	}


event bro_init()
	{
	set_buf(ll_file, F);
	precompile_load_level_filters();
	set_load_level(default_load_level);

	# Don't adjust the filter when reading a trace.
	if ( ! reading_live_traffic() )
		can_adjust_filter = F;
	}
