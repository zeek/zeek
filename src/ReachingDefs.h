// See the file "COPYING" in the main distribution directory for copyright.

#include "DefItem.h"


typedef std::map<const DefinitionItem*, DefinitionPoint> ReachingDefsMap;

class ReachingDefs {
public:
	void AddRDs(const ReachingDefs& rd)
		{
		auto& rd_m = rd.RDMap();

		for ( const auto& one_rd : rd_m )
			AddRD(one_rd.first, one_rd.second);
		}

	void AddRD(const DefinitionItem* di, DefinitionPoint dp)
		{
		rd_map.insert(ReachingDefsMap::value_type(di, dp));
		}

	bool HasDI(const DefinitionItem* di) const
		{
		return rd_map.find(di) != rd_map.end();
		}

	bool HasPair(const DefinitionItem* di, DefinitionPoint dp) const
		{
		auto l = rd_map.find(di);
		return l != rd_map.end() && l->second.SameAs(dp);
		}

	ReachingDefs Intersect(const ReachingDefs& r) const;
	ReachingDefs Union(const ReachingDefs& r) const;

	bool Differ(const ReachingDefs& r) const;

	void Dump() const;

	int Size() const	{ return rd_map.size(); }

protected:
	const ReachingDefsMap& RDMap() const	{ return rd_map; }

	void PrintRD(const DefinitionItem* di, const DefinitionPoint& dp) const;

	ReachingDefsMap rd_map;
};

static ReachingDefs null_RDs;
