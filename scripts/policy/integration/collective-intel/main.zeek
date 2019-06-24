
@load base/frameworks/intel

module Intel;

export {
	redef record Intel::MetaData += {
		cif_tags: string &optional;
		cif_confidence: double &optional;
		cif_source: string &optional;
		cif_description: string &optional;
		cif_firstseen: string &optional;
		cif_lastseen: string &optional;
	};

	type CIF: record {
		tags: string &optional &log;
		confidence: double &optional &log;
		source: string &optional &log;
		description: string &optional &log;
		firstseen: string &optional &log;
		lastseen: string &optional &log;
	};

	redef record Info += {
		cif: CIF &log &optional;
	};

}

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=5
	{
	for ( item in items )
		{
		local tmp: CIF;

		if ( item$meta?$cif_tags )
			tmp$tags = item$meta$cif_tags;
		if ( item$meta?$cif_confidence )
			tmp$confidence = item$meta$cif_confidence;
		if ( item$meta?$cif_source )
			tmp$source = item$meta$cif_source;
		if ( item$meta?$cif_description )
			tmp$description = item$meta$cif_description
		if ( item$meta?$cif_firstseen )
			tmp$firstseen = item$meta$cif_firtseen;
		if ( item$meta?$cif_lastseen )
			tmp$lastseen = item$meta$cif_lastseen;

		info$cif = tmp;
	}
}
