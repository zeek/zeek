// See the file "COPYING" in the main distribution directory for copyright.

#include "ReachingDefs.h"
#include "Desc.h"


static char obj_desc_storage[8192];

static const char* obj_desc(const BroObj* o)
	{
	ODesc d;
	d.SetDoOrig(false);
	o->Describe(&d);
	d.SP();
	o->GetLocationInfo()->Describe(&d);

	strcpy(obj_desc_storage, d.Description());

	return obj_desc_storage;
	}

ReachingDefs::ReachingDefs()
	{
	my_rd_map = new ReachingDefsMap;
	const_rd_map = nullptr;
	}

ReachingDefs::ReachingDefs(RD_ptr& rd)
	{
	const_rd_map = rd;
	my_rd_map = nullptr;
	}

ReachingDefs::~ReachingDefs()
	{
	if ( my_rd_map )
		{
		for ( auto& one_rd : *my_rd_map )
			// ### To do: figure out if we need to go through
			// the PList and delete its elements.
			delete one_rd.second;

		delete my_rd_map;
		}
	}

void ReachingDefs::AddRD(const DefinitionItem* di, const DefinitionPoint& dp)
	{
	if ( HasPair(di, dp) )
		return;

	CopyMapIfNeeded();

	auto curr_defs = my_rd_map->find(di);

	if ( curr_defs == my_rd_map->end() )
		{
		auto dps = new List<DefinitionPoint>();
		dps->push_back(dp);
		my_rd_map->insert(ReachingDefsMap::value_type(di, dps));
		}

	else
		{
		auto dps = curr_defs->second;
		dps->push_back(dp);
		}
	}

void ReachingDefs::AddOrFullyReplace(const DefinitionItem* di,
					const DefinitionPoint& dp)
	{
	CopyMapIfNeeded();

	auto curr_defs = my_rd_map->find(di);

	if ( curr_defs != my_rd_map->end() )
		my_rd_map->erase(curr_defs);

	AddRD(di, dp);
	}

RD_ptr ReachingDefs::Intersect(const RD_ptr& r) const
	{
	auto res = make_new_RD_ptr();

	for ( const auto& i : *RDMap() )
		for ( const auto& dp : *i.second )
			if ( r->HasPair(i.first, dp) )
				res->AddRD(i.first, dp);

	return res;
	}

RD_ptr ReachingDefs::Union(const RD_ptr& r) const
	{
	auto res = make_new_RD_ptr();

	res->AddRDs(r);

	for ( const auto& i : *RDMap() )
		for ( const auto& dp : *i.second )
			res->AddRD(i.first, dp);

	return res;
	}

RD_ptr ReachingDefs::IntersectWithConsolidation(const RD_ptr& r,
						const DefinitionPoint& di) const
	{
	auto res = make_new_RD_ptr();

	for ( const auto& i : *RDMap() )
		for ( const auto& dp : *i.second )
			{
			if ( r->HasPair(i.first, dp) )
				res->AddRD(i.first, dp);

			else if ( r->HasDI(i.first) &&
				  ! res->HasPair(i.first, di) )
				res->AddRD(i.first, di);
			}

	return res;
	}

bool ReachingDefs::HasPair(const DefinitionItem* di, const DefinitionPoint& dp)
const
	{
	auto map = RDMap();

	auto l = map->find(di);
	if ( l == map->end() )
		return false;

	for ( const auto& l_dp : *l->second )
		if ( l_dp.SameAs(dp) )
			return true;

	return false;
	}

void ReachingDefs::AddRDs(const ReachingDefsMap* rd_m)
	{
	if ( rd_m->size() == 0 )
		return;

	for ( const auto& one_rd : *rd_m )
		for ( const auto& dp : *one_rd.second )
			AddRD(one_rd.first, dp);
	}

void ReachingDefs::CopyMapIfNeeded()
	{
	if ( my_rd_map )
		return;

	my_rd_map = new ReachingDefsMap;
	auto old_const_rd_map = const_rd_map;
	const_rd_map = nullptr;
	AddRDs(old_const_rd_map);
	}

void ReachingDefs::Dump() const
	{
	DumpMap(RDMap());
	}

void ReachingDefs::DumpMap(const ReachingDefsMap* map) const
	{
	printf("%d RD element%s: ", Size(), Size() == 1 ? "" : "s");

	int n = 0;
	for ( auto r = map->begin(); r != map->end(); ++r )
		{
		if ( ++n > 1 )
			printf(", ");

		PrintRD(r->first, r->second);
		}

	printf("\n");
	}

void ReachingDefs::PrintRD(const DefinitionItem* di,
				const DefPoints& dps) const
	{
	printf("%s (%d)", di->Name(), dps->length());
	}


RD_ptr& ReachingDefSet::FindRDs(const BroObj* o) const
	{
	auto rd = a_i->find(o);
	if ( rd == a_i->end() )
		{
		printf("miscall object: %s\n", obj_desc(o));
		Internal("miscall of ReachingDefSet::FindRDs");
		}

	return rd->second;
	}

void ReachingDefSet::AddOrReplace(const BroObj* o, const DefinitionItem* di,
					const DefinitionPoint& dp)
	{
	auto rd = a_i->find(o);
	if ( rd == a_i->end() )
		{
		printf("miscall object: %s\n", obj_desc(o));
		Internal("miscall of ReachingDefSet::AddOrReplace");
		}

	rd->second->AddOrFullyReplace(di, dp);
	}
