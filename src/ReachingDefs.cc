// See the file "COPYING" in the main distribution directory for copyright.

#include "ReachingDefs.h"


ReachingDefs::ReachingDefs()
	{
	my_rd_map = new ReachingDefsMap;
	const_rd_map = my_rd_map;
	}

ReachingDefs::ReachingDefs(const ReachingDefs* rd)
	{
	const_rd_map = rd->RDMap();
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

void ReachingDefs::AddRD(const DefinitionItem* di, DefinitionPoint dp)
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
					DefinitionPoint dp)
	{
	auto curr_defs = my_rd_map->find(di);

	if ( curr_defs != my_rd_map->end() )
		my_rd_map->erase(curr_defs);

	AddRD(di, dp);
	}

RD_ptr ReachingDefs::Intersect(const RD_ptr& r) const
	{
	auto res = make_new_RD_ptr();

	for ( const auto& i : *const_rd_map )
		for ( const auto& dp : *i.second )
			if ( r->HasPair(i.first, dp) )
				res->AddRD(i.first, dp);

	return res;
	}

RD_ptr ReachingDefs::Union(const RD_ptr& r) const
	{
	auto res = make_new_RD_ptr();

	for ( const auto& i : *const_rd_map )
		for ( const auto& dp : *i.second )
			if ( ! r->HasPair(i.first, dp) )
				res->AddRD(i.first, dp);

	return res;
	}

bool ReachingDefs::HasPair(const DefinitionItem* di, DefinitionPoint dp) const
	{
	auto l = const_rd_map->find(di);

	if ( l == const_rd_map->end() )
		return false;

	for ( const auto& l_dp : *l->second )
		if ( l_dp.SameAs(dp) )
			return true;

	return false;
	}

void ReachingDefs::AddRDs(const ReachingDefsMap* rd_m)
	{
	for ( const auto& one_rd : *rd_m )
		for ( auto& dp : *one_rd.second )
			AddRD(one_rd.first, dp);
	}

void ReachingDefs::CopyMapIfNeeded()
	{
	if ( my_rd_map )
		return;

	my_rd_map = new ReachingDefsMap;
	AddRDs(const_rd_map);

	const_rd_map = my_rd_map;
	}

void ReachingDefs::Dump() const
	{
	if ( Size() == 0 )
		{
		printf("<none>\n");
		return;
		}

	for ( auto r = const_rd_map->begin(); r != const_rd_map->end(); ++r )
		PrintRD(r->first, r->second);
	}

void ReachingDefs::PrintRD(const DefinitionItem* di,
				const DefPoints& dps) const
	{
	int n = dps->length();
	printf("%d RD%s for %s\n", n, n > 1 ? "s" : "", di->Name());
	}


const RD_ptr& ReachingDefSet::FindRDs(const BroObj* o) const
	{
	auto rd = a_i->find(o);
	if ( rd == a_i->end() )
		Internal("miscall of ReachingDefSet::FindRDs");

	return rd->second;
	}

void ReachingDefSet::AddOrReplace(const BroObj* o, const DefinitionItem* di,
					DefinitionPoint dp)
	{
	auto rd = a_i->find(o);
	if ( rd == a_i->end() )
		Internal("miscall of ReachingDefSet::AddOrReplace");

	return rd->second->AddOrFullyReplace(di, dp);
	}

