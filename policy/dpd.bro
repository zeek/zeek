# $Id: dpd.bro,v 1.1.2.1 2006/05/10 02:10:26 sommer Exp $
#
# Activates port-independent protocol detection.

redef signature_files += "dpd.sig";


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

