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

typedef std::map<const BroObj*, ReachingDefs> AnalyInfo;

static ReachingDefs null_RDs;

// Reaching definitions associated with a collection of BroObj's.
class ReachingDefSet {
public:
	ReachingDefSet(DefItemMap& _item_map) : item_map(_item_map)
		{
		a_i = new AnalyInfo;
		}

	~ReachingDefSet()
		{
		delete a_i;
		}

	bool HasRDs(const BroObj* o) const
		{
		auto RDs = a_i->find(o);
		return RDs != a_i->end();
		}

	bool HasRD(const BroObj* o, const ID* id) const
		{
		return HasRD(o, item_map.GetConstIDReachingDef(id));
		}

	bool HasRD(const BroObj* o, const DefinitionItem* di) const
		{
		auto RDs = a_i->find(o);
		if ( RDs == a_i->end() )
			return false;

		return RDs->second.HasDI(di);
		}

	const ReachingDefs& RDs(const BroObj* o) const
		{
		if ( o == nullptr )
			return null_RDs;

		auto rd = a_i->find(o);
		if ( rd != a_i->end() )
			return rd->second;
		else
			return null_RDs;
		}

	void AddRDs(const BroObj* o, const ReachingDefs& rd)
		{
		if ( HasRDs(o) )
			MergeRDs(o, rd);
		else
			a_i->insert(AnalyInfo::value_type(o, rd));
		}

protected:
	void MergeRDs(const BroObj* o, const ReachingDefs& rd)
		{
		auto& curr_rds = a_i->find(o)->second;
		curr_rds.AddRDs(rd);
		}

	AnalyInfo* a_i;
	DefItemMap& item_map;
};
