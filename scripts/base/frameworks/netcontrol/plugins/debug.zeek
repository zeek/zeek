##! Debugging plugin for the NetControl framework, providing insight into
##! executed operations.

@load ../plugin
@load ../main

module NetControl;

export {
	## Instantiates a debug plugin for the NetControl framework. The debug
	## plugin simply logs the operations it receives.
	##
	## do_something: If true, the plugin will claim it supports all operations; if
	##               false, it will indicate it doesn't support any.
	global create_debug: function(do_something: bool) : PluginState;
}

function do_something(p: PluginState) : bool
	{
	return p$config["all"] == "1";
	}

function debug_name(p: PluginState) : string
	{
	return fmt("Debug-%s", (do_something(p) ? "All" : "None"));
	}

function debug_log(p: PluginState, msg: string)
	{
	print fmt("netcontrol debug (%s): %s", debug_name(p), msg);
	}

function debug_init(p: PluginState)
	{
	debug_log(p, "init");
	plugin_activated(p);
	}

function debug_done(p: PluginState)
	{
	debug_log(p, "init");
	}

function debug_add_rule(p: PluginState, r: Rule) : bool
	{
	local s = fmt("add_rule: %s", r);
	debug_log(p, s);

	if ( do_something(p) )
		{
		event NetControl::rule_added(r, p);
		return T;
		}

	return F;
	}

function debug_remove_rule(p: PluginState, r: Rule, reason: string) : bool
	{
	local s = fmt("remove_rule (%s): %s", reason, r);
	debug_log(p, s);

	event NetControl::rule_removed(r, p);
	return T;
	}

global debug_plugin = Plugin(
	$name=debug_name,
	$can_expire = F,
	$init = debug_init,
	$done = debug_done,
	$add_rule = debug_add_rule,
	$remove_rule = debug_remove_rule
	);

function create_debug(do_something: bool) : PluginState
	{
	local p: PluginState = [$plugin=debug_plugin];

	# FIXME: Why's the default not working?
	p$config = table();
	p$config["all"] = (do_something ? "1" : "0");

	return p;
	}
