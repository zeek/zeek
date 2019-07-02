
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

	type CIF: record {
		## This creates a CIF record to append the CIF values for more consistent formatting
		tags: string &optional &log;
		confidence: double &optional &log;
		source: string &optional &log;
		description: string &optional &log;
		firstseen: string &optional &log;
		lastseen: string &optional &log;
	};

	redef record Info += {
		## Adds the CIF record to the Info record
		cif: CIF &log &optional;
	};

}

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=5
	{
	for ( item in items )
		{
		## Creates a local CIF record to assign data to
		local tmp: CIF;

		## Checks to see if the cif_tags field is populated and add it to the local record
		if ( item$meta?$cif_tags )
			tmp$tags = item$meta$cif_tags;
		## Checks to see if the cif_confidence field is populated and add it to the local record
		if ( item$meta?$cif_confidence )
			tmp$confidence = item$meta$cif_confidence;
		## Checks to see if the cif_source field is populated and add it to the local record
		if ( item$meta?$cif_source )
			tmp$source = item$meta$cif_source;
		## Checks to see if the cif_description field is populated and add it to the local record
		if ( item$meta?$cif_description )
			tmp$description = item$meta$cif_description;
		## Checks to see if the cif_firstseen field is populated and add it to the local record
		if ( item$meta?$cif_firstseen )
			tmp$firstseen = item$meta$cif_firstseen;
		## Checks to see if the cif_lastseen field is populated and add it to the local record
		if ( item$meta?$cif_lastseen )
			tmp$lastseen = item$meta$cif_lastseen;

		## Add the local CIF record to the Info CIF placeholder, so it wil be added to intel.log
		info$cif = tmp;
	}
}
