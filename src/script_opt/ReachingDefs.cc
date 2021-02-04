// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ReachingDefs.h"
#include "Desc.h"


namespace zeek::detail {


ReachingDefs::ReachingDefs()
	{
	my_rd_map = std::make_shared<ReachingDefsMap>();
	const_rd_map = nullptr;
	}

ReachingDefs::ReachingDefs(RDPtr rd)
	{
	const_rd_map = rd->RDMap();
	my_rd_map = nullptr;
	}

void ReachingDefs::AddRD(const DefinitionItem* di, const DefinitionPoint& dp)
	{
	if ( HasPair(di, dp) )
		return;

	CopyMapIfNeeded();

	auto curr_defs = my_rd_map->find(di);

	if ( curr_defs == my_rd_map->end() )
		{
		auto dps = std::make_unique<List<DefinitionPoint>>();
		dps->push_back(dp);
		(*my_rd_map)[di] = std::move(dps);
		}

	else
		{
		auto& dps = curr_defs->second;
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

RDPtr ReachingDefs::Intersect(const RDPtr& r) const
	{
	// The following is used when there are different definitions for
	// the same item in the intersection, as a way to capture "it will
	// be defined", but not providing a specific point-of-definition
	// (since it's ambiguous which one in particular to use).
	static DefinitionPoint multi_dps;

	auto res = make_intrusive<ReachingDefs>();

	for ( const auto& i : *RDMap() )
		for ( const auto& dp : *i.second )
			{
			if ( r->HasPair(i.first, dp) )
				// Same definition present in both.
				res->AddRD(i.first, dp);

			else if ( r->HasDI(i.first) )
				// There's a definition in r, just not the same
				// one.  Mark as present-but-not-specific.
				res->AddRD(i.first, multi_dps);
			}

	return res;
	}

RDPtr ReachingDefs::Union(const RDPtr& r) const
	{
	auto res = make_intrusive<ReachingDefs>();

	res->AddRDs(r);

	for ( const auto& i : *RDMap() )
		for ( const auto& dp : *i.second )
			res->AddRD(i.first, dp);

	return res;
	}

RDPtr ReachingDefs::IntersectWithConsolidation(const RDPtr& r,
						const DefinitionPoint& di) const
	{
	// Same notion as for the Intersect method.
	static DefinitionPoint multi_dps;

	auto res = make_intrusive<ReachingDefs>();

	for ( const auto& i : *RDMap() )
		for ( const auto& dp : *i.second )
			{
			if ( r->HasPair(i.first, dp) )
				// Item and definition point are shared,
				// include in result.
				res->AddRD(i.first, dp);
			else
				// Regardless of whether r has the item,
				// treat it as such and capture this as
				// a multi-definition-point definition.
				res->AddRD(i.first, multi_dps);
			}

	return res;
	}

bool ReachingDefs::HasPair(const DefinitionItem* di, const DefinitionPoint& dp)
const
	{
	const auto& map = RDMap();

	auto l = map->find(di);
	if ( l == map->end() )
		return false;

	for ( const auto& l_dp : *l->second )
		if ( l_dp.SameAs(dp) )
			return true;

	return false;
	}

void ReachingDefs::AddRDs(const std::shared_ptr<ReachingDefsMap>& rd_m)
	{
	for ( const auto& one_rd : *rd_m )
		for ( const auto& dp : *one_rd.second )
			AddRD(one_rd.first, dp);
	}

void ReachingDefs::CopyMapIfNeeded()
	{
	if ( my_rd_map )
		return;

	my_rd_map = std::make_shared<ReachingDefsMap>();
	auto old_const_rd_map = std::move(const_rd_map);
	const_rd_map = nullptr;
	AddRDs(old_const_rd_map);
	}

void ReachingDefs::Dump() const
	{
	DumpMap(RDMap());
	}

void ReachingDefs::DumpMap(const std::shared_ptr<ReachingDefsMap>& map) const
	{
	printf("%d RD element%s: ", Size(), Size() == 1 ? "" : "s");

	int n = 0;
	for ( auto r = map->begin(); r != map->end(); ++r )
		{
		if ( ++n > 1 )
			printf(", ");

		PrintRD(r->first, r->second.get());
		}

	printf("\n");
	}

void ReachingDefs::PrintRD(const DefinitionItem* di, const DefPoints* dps) const
	{
	printf("%s (", di->Name());

	loop_over_list(*dps, i)
		{
		if ( i > 0 )
			printf(",");
		printf("%lx", (unsigned long) (*dps)[i].OpaqueVal());
		}

	printf(")");
	}


const RDPtr& ReachingDefSet::FindRDs(const Obj* o) const
	{
	auto rd = a_i.find(o);
	if ( rd == a_i.end() )
		{
		static RDPtr empty_rds;
		return empty_rds;
		}

	return rd->second;
	}

void ReachingDefSet::AddOrReplace(const Obj* o, const DefinitionItem* di,
					const DefinitionPoint& dp)
	{
	auto rd = a_i.find(o);
	ASSERT(rd != a_i.end());
	rd->second->AddOrFullyReplace(di, dp);
	}


} // zeek::detail
