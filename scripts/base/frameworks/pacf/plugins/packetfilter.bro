# PACF plugin for the PacketFilter handling that comes with
# Bro. Since the PacketFilter in Bro is quite limited in scope
# and can only add/remove filters for addresses, this is quite
# limited in scope at the moment.

module Pacf;

@load ../plugin

export {
	## Instantiates the packetfilter plugin.
	global create_packetfilter: function() : PluginState;
}

# Check if we can handle this rule. If it specifies ports or
# anything Bro cannot handle, simply ignore it for now.
function packetfilter_check_rule(r: Rule) : bool
	{
	if ( r$ty != DROP )
		return F;

	if ( r$target != MONITOR )
		return F;

	local e = r$entity;
	if ( e$ty == ADDRESS )
		return T;

	if ( e$ty != FLOW ) # everything else requires ports or MAC stuff
		return F;

	if ( e$flow?$src_p || e$flow?$dst_p || e$flow?$src_m || e$flow?$dst_m )
		return F;

	return T;
	}


function packetfilter_add_rule(p: PluginState, r: Rule) : bool
	{
	if ( ! packetfilter_check_rule(r) )
		return F;

	local e = r$entity;
	if ( e$ty == ADDRESS )
		{
		install_src_net_filter(e$ip, 0, 1.0);
		install_dst_net_filter(e$ip, 0, 1.0);
		return T;
		}

	if ( e$ty == FLOW )
		{
		local f = e$flow;
		if ( f?$src_h )
			install_src_net_filter(f$src_h, 0, 1.0);
		if ( f?$dst_h )
			install_dst_net_filter(f$dst_h, 0, 1.0);

		return T;
		}

	return F;
	}

function packetfilter_remove_rule(p: PluginState, r: Rule) : bool
	{
	if ( ! packetfilter_check_rule(r) )
		return F;
	
	local e = r$entity;
	if ( e$ty == ADDRESS )
		{
		uninstall_src_net_filter(e$ip);
		uninstall_dst_net_filter(e$ip);
		return T;
		}

	if ( e$ty == FLOW )
		{
		local f = e$flow;
		if ( f?$src_h )
			uninstall_src_net_filter(f$src_h);
		if ( f?$dst_h )
			uninstall_dst_net_filter(f$dst_h);

		return T;
		}

	return F;
	}

function packetfilter_name(p: PluginState) : string
	{
	return "PACF plugin for the Bro packetfilter";
	}

global packetfilter_plugin = Plugin(
	$name=packetfilter_name,
	$can_expire = F,
#	$init = packetfilter_init,
#	$done = packetfilter_done,
	$add_rule = packetfilter_add_rule,
	$remove_rule = packetfilter_remove_rule
	);

function create_packetfilter() : PluginState
	{
	local p: PluginState = [$plugin=packetfilter_plugin];

	return p;
	}

