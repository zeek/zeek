# $Id: worm.bro 4758 2007-08-10 06:49:23Z vern $

@load notice
@load site

# signatures.bro needs this.
global is_worm_infectee: function(ip: addr) : bool;

@load signatures

redef enum Notice += {
	LocalWorm,		# worm seen in local host
	RemoteWorm,		# worm seen in remote host
};

# redef capture_filters += { ["worm"] = "tcp dst port 80" };

const worm_log = open_log_file("worm") &redef;

# Maps types of worms to URI patterns.
const worm_types: table[string] of pattern = {
	["Code Red 1"] = /\.id[aq]\?.*NNNNNNNNNNNNN/,
	["Code Red 2"] = /\.id[aq]\?.*XXXXXXXXXXXXX/,
	["Nimda"] = /\/scripts\/root\.exe\?\/c\+tftp/ |
			/\/MSADC\/root.exe\?\/c\+dir/ |
			/cool\.dll.*httpodbc\.dll/,	# 29Oct01 Nimda variant
} &redef;

# Maps signatures to worm types.
const worm_sigs: table[string] of string = {
	["slammer"] = "Slammer",
	["nimda"] = "Nimda",
	["bagle-bc"] = "Bagle.bc"
};

# We handle these ourselves.
redef signature_actions += {
	["codered1"] = SIG_IGNORE,
	["codered2"] = SIG_IGNORE,
	["slammer"] = SIG_IGNORE,
	["nimda"] = SIG_IGNORE,
	["bagle-bc"] = SIG_IGNORE
};

# Indexed by infectee.
global worm_list: table[addr] of count &default=0 &read_expire = 2 days;

# Indexed by infectee and type of worm.
global worm_type_list: table[addr, string] of count
					&default=0 &read_expire = 2 days;

# Invoked each time a new infectee (or a new type of worm for an existing
# infectee) is seen.  For the first instance of any type for a new infectee,
# two events will be generated, one with worm_type of "first instance",
# and another with the particular worm type.
global worm_infectee_seen: event(c: connection, is_local: bool, worm_type: string);

# Invoked whenever connection c has included a URI of worm type "worm_type".
event worm_instance(c: connection, worm_type: string)
	{
	local id = c$id;
	local src = id$orig_h;
	local is_local = is_local_addr(src);

	if ( ++worm_list[src] == 1 )
		event worm_infectee_seen(c, is_local, "first instance");

	if ( ++worm_type_list[src, worm_type] == 1 )
		event worm_infectee_seen(c, is_local, worm_type);
	}

event worm_infectee_seen(c: connection, is_local: bool, worm_type: string)
	{
	if ( worm_type == "first instance" )
		return;	# just do the reporting for the specific type

	local infectee = c$id$orig_h;
	local where = is_local ? "local" : "remote";
	local msg = fmt("%s %s worm source: %s", where, worm_type, infectee);

	if ( is_local )
		NOTICE([$note=LocalWorm, $conn=c, $src=infectee,
			$msg=msg, $sub=worm_type]);
	else
		NOTICE([$note=RemoteWorm, $conn=c, $src=infectee,
			$msg=msg, $sub=worm_type]);

	print worm_log, fmt("%.6f %s", network_time(), msg);
	}

event http_request(c: connection, method: string,
		   original_URI: string, unescaped_URI: string, version: string)
	{
	# It's a pity to do this as a loop.  Better would be if Bro could
	# search the patterns as one large RE and note which matched.

	for ( wt in worm_types )
		if ( worm_types[wt] in unescaped_URI )
			event worm_instance(c, wt);
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	if ( state$id in worm_sigs )
		event worm_instance(state$conn, worm_sigs[state$id]);
	}

# Ignore "weird" events, we get some due to the capture_filter above that
# only captures the client side of an HTTP session.
event conn_weird(name: string, c: connection)
	{
	}

function is_worm_infectee(ip: addr): bool
	{
	return ip in worm_list;
	}
