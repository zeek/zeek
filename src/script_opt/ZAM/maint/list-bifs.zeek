# Prints to stdout an alphabetized list of all of the BiFs registered with Zeek. 
event zeek_init()
	{
	local bifs: vector of string;

	for ( gn, gi in global_ids() )
		if ( /^function/ in gi$type_name && gi?$value && fmt("%s", gi$value) == gn )
			bifs += gn;

	bifs = sort(bifs, strcmp);

	for ( _, b in bifs )
		print b;
	}
