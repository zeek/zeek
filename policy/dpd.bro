##! Activates port-independent protocol detection.
@load signatures

redef signature_files += "dpd.sig";

event bro_init()
	{
	for ( a in dpd_config )
		{
		for ( p in dpd_config[a]$ports )
			{
			if ( p !in dpd_analyzer_ports )
				dpd_analyzer_ports[p] = set();
			add dpd_analyzer_ports[p][a];
			}
		}
	}

event protocol_confirmation(c: connection, atype: count, aid: count)
	{
	delete c$service[fmt("-%s",analyzer_name(atype))];
	add c$service[analyzer_name(atype)];
	}

event protocol_violation(c: connection, atype: count, aid: count,
				reason: string) &priority = 10
	{
	delete c$service[analyzer_name(atype)];
	add c$service[fmt("-%s",analyzer_name(atype))];
	}

