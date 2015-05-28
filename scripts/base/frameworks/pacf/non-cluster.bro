module Pacf;

@load ./main

function activate(p: PluginState, priority: int)
	{
	activate_impl(p, priority);
	}

function add_rule(r: Rule) : string
	{
	return add_rule_impl(r);
	}

function remove_rule(id: string) : bool
	{
	return remove_rule_impl(id);
	}
