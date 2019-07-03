@load base/frameworks/intel

module Intel;

## This file adds mapping between the Collective Intelligence Framework (CIF) and Zeek.

export {
	redef record Intel::MetaData += {
		## Maps to the 'tags' fields in CIF
		cif_tags: string &optional;
		## Maps to the 'confidence' field in CIF
		cif_confidence: double &optional;
		## Maps to the 'source' field in CIF
		cif_source: string &optional;
		## Maps to the 'description' field in CIF
		cif_description: string &optional;
		## Maps to the 'firstseen' field in CIF
		cif_firstseen: string &optional;
		## Maps to the 'lastseen' field in CIF
		cif_lastseen: string &optional;
	};

	## CIF record used for consistent formatting of CIF values.
	type CIF: record {
		## CIF tags observations, examples for tags are ``botnet`` or ``exploit``.
		tags: string &optional &log;
		## In CIF Confidence details the degree of certainty of a given observation.
		confidence: double &optional &log;
		## Source given in CIF.
		source: string &optional &log;
		## description given in CIF.
		description: string &optional &log;
		## First time the source observed the behavior.
		firstseen: string &optional &log;
		## Last time the source observed the behavior.
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
			tmp$description = item$meta$cif_description;
		if ( item$meta?$cif_firstseen )
			tmp$firstseen = item$meta$cif_firstseen;
		if ( item$meta?$cif_lastseen )
			tmp$lastseen = item$meta$cif_lastseen;

		info$cif = tmp;
		}
	}
