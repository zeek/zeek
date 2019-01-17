module NetControl;

export {
	## Instantiates the plugin.
	global create_skeleton: function(argument: string) : PluginState;
}

function skeleton_name(p: PluginState) : string
	{
	return "NetControl skeleton plugin";
	}

function skeleton_add_rule_fun(p: PluginState, r: Rule) : bool
	{
	print "add", r;
	event NetControl::rule_added(r, p);
	return T;
	}

function skeleton_remove_rule_fun(p: PluginState, r: Rule, reason: string &default="") : bool
	{
	print "remove", r;
	event NetControl::rule_removed(r, p);
	return T;
	}

global skeleton_plugin = Plugin(
	$name = skeleton_name,
	$can_expire = F,
	$add_rule = skeleton_add_rule_fun,
	$remove_rule = skeleton_remove_rule_fun
	);

function create_skeleton(argument: string) : PluginState
	{
	local p = PluginState($plugin=skeleton_plugin);

	return p;
	}
