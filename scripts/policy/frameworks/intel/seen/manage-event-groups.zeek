@load frameworks/intel/seen
@load base/frameworks/reporter

module Intel;

export {
	## Whether Intel event groups for the seen scripts are managed.
	##
	## When loading this script, by default, all :zeek:see:`Intel::Type`
	## event groups are disabled at startup and only enabled when indicators
	## of corresponding types are loaded into the Intel framework's store.
	## This allows to load the ``frameworks/intel/seen`` scripts without
	## incurring event handling overhead when no Intel indicators are loaded.
	##
	## One caveat is that the :zeek:see:`Intel::seen_policy` hook will not
	## be invoked for indicator types that are not at all in the Intel
	## framework's store. If you rely on :zeek:see:`Intel::seen_policy` to
	## find unmatched indicators, do not not load this script, set this
	## variable to ``F``, or insert dummy values of the types using
	## :zeek:see:`Intel::insert`.
	const manage_seen_event_groups = T &redef;
}

global intel_type_counts: table[Intel::Type] of count &default=0;

event zeek_init()
	{
	# If the feature is disabled, don't act.
	if ( ! manage_seen_event_groups )
		return;

	# Disable all Intel related event groups at startup. These
	# are enabled again as soon as at least one indicator of the
	# type is inserted.
	for ( name in enum_names(Intel::Type) )
		{
		if ( has_event_group(name) )
			disable_event_group(name);
		}
	}

hook Intel::indicator_inserted(v: string, t: Intel::Type)
	{
	++intel_type_counts[t];

	if ( ! manage_seen_event_groups )
		return;


	if ( intel_type_counts[t] == 1 )
		{
		local name = cat(t);

		if ( has_event_group(name) )
			enable_event_group(name);
		}
	}

hook Intel::indicator_removed(v: string, t: Intel::Type)
	{
	--intel_type_counts[t];

	if ( ! manage_seen_event_groups )
		return;


	if ( intel_type_counts[t] == 0 )
		{
		local name = cat(t);

		if ( has_event_group(name) )
			disable_event_group(name);
		}
	}
