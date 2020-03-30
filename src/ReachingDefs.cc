// See the file "COPYING" in the main distribution directory for copyright.

#include "ReachingDefs.h"


ReachingDefs* ReachingDefs::Intersect(const ReachingDefs* r) const
	{
	ReachingDefs* res = new ReachingDefs;

	auto i = rd_map.begin();
	while ( i != rd_map.end() )
		{
		if ( r->HasPair(i->first, i->second) )
			res->AddRD(i->first, i->second);

		++i;
		}

	return res;
	}

ReachingDefs* ReachingDefs::Union(const ReachingDefs* r) const
	{
	ReachingDefs* res = new ReachingDefs;

	auto i = rd_map.begin();
	while ( i != rd_map.end() )
		{
		if ( ! r->HasPair(i->first, i->second) )
			res->AddRD(i->first, i->second);

		++i;
		}

	return res;
	}

void ReachingDefs::Dump() const
	{
	if ( Size() == 0 )
		{
		printf("<none>\n");
		return;
		}

	for ( auto r = rd_map.begin(); r != rd_map.end(); ++r )
		PrintRD(r->first, r->second);
	}

void ReachingDefs::PrintRD(const DefinitionItem* di,
				const DefinitionPoint& dp) const
	{
	printf("RD for %s\n", di->Name());
	}
