
@load ./main

module NetControl;

function activate(p: PluginState, priority: int)
	{
	activate_impl(p, priority);
	}

function add_rule(r: Rule) : string
	{
	return add_rule_impl(r);
	}

function delete_rule(id: string, reason: string &default="") : bool
	{
	return delete_rule_impl(id, reason);
	}

function remove_rule(id: string, reason: string &default="") : bool
	{
	return remove_rule_impl(id, reason);
	}

event rule_expire(r: Rule, p: PluginState) &priority=-5
	{
	rule_expire_impl(r, p);
	}

event rule_exists(r: Rule, p: PluginState, msg: string) &priority=5
	{
	rule_added_impl(r, p, T, msg);

	if ( r?$expire && r$expire > 0secs && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };
	}

event rule_added(r: Rule, p: PluginState, msg: string) &priority=5
	{
	rule_added_impl(r, p, F, msg);

	if ( r?$expire && r$expire > 0secs && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };
	}

event rule_removed(r: Rule, p: PluginState, msg: string) &priority=-5
	{
	rule_removed_impl(r, p, msg);
	}

event rule_timeout(r: Rule, i: FlowInfo, p: PluginState) &priority=-5
	{
	rule_timeout_impl(r, i, p);
	}

event rule_error(r: Rule, p: PluginState, msg: string) &priority=-5
	{
	rule_error_impl(r, p, msg);
	}

