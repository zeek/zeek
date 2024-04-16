# Prints to stdout an alphabetized list of all of the BiFs registered with Zeek. 
event zeek_init()
	{
	local bifs: vector of string;

	for ( gn, gi in global_ids() )
		if ( gi$type_name == "func" && gi?$value && fmt("%s", gi$value) == gn )
			bifs += gn;

	bifs = sort(bifs, strcmp);

	for ( _, b in bifs )
		print b;
	}
