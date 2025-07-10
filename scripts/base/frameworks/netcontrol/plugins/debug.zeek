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
	##
	## name: Optional name that for the plugin.
	global create_debug: function(do_something: bool, name: string &default="") : PluginState;

	## Instantiates a debug plugin for the NetControl framework. This variation
	## of the plugin will return "exists" to any rule operations.
	##
	## name: Name of this plugin.
	global create_debug_exists: function(name: string) : PluginState;

	## Instantiates a debug plugin for the NetControl framework. This variation
	## of the plugin will return "error" to any rule operations.
	##
	## name: Name of this plugin.
	global create_debug_error: function(name: string) : PluginState;
}

function do_something(p: PluginState) : bool
	{
	return p$config["all"] == "1";
	}

function debug_name(p: PluginState) : string
	{
	return p$config["name"];
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

function debug_add_rule_exists(p: PluginState, r: Rule) : bool
	{
	local s = fmt("add_rule_exists: %s", r);
	debug_log(p, s);

	if ( do_something(p) )
		{
		event NetControl::rule_exists(r, p);
		return T;
		}

	return F;
	}

function debug_add_rule_error(p: PluginState, r: Rule) : bool
	{
	local s = fmt("add_rule_error: %s", r);
	debug_log(p, s);

	if ( do_something(p) )
		{
		event NetControl::rule_error(r, p, "debug error");
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

function create_debug(do_something: bool, name: string) : PluginState
	{
	local p = PluginState($plugin=debug_plugin);

	# FIXME: Why's the default not working?
	p$config = table();
	p$config["all"] = (do_something ? "1" : "0");
	if ( name == "" )
		p$config["name"] = fmt("Debug-%s", (do_something ? "All" : "None"));
	else
		p$config["name"] = name;

	return p;
	}

function create_debug_error(name: string) : PluginState
	{
	local p = copy(PluginState($plugin=debug_plugin));
	p$config["name"] = name;
	p$config["all"] = "1";
	p$plugin$add_rule = debug_add_rule_error;
	return p;
	}

function create_debug_exists(name: string) : PluginState
	{
	local p = copy(PluginState($plugin=debug_plugin));
	p$config["name"] = name;
	p$config["all"] = "1";
	p$plugin$add_rule = debug_add_rule_exists;
	return p;
	}
