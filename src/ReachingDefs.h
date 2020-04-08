// See the file "COPYING" in the main distribution directory for copyright.

#include "DefItem.h"


// Maps a DefinitionItem (i.e., a variable or a record field within a
// DefinitionItem) to a list of all the points where the item is defined.
//
// Those points are specific to a given location in a script (see
// AnalyInfo below).  For example, right after an assignment to a variable,
// it will have exactly one associated point (the assignment).  But at
// other points there can be more than one reaching definition; for example,
// a variable defined in both branches of an if-else will cause the location
// in the script after the if-else statement to have both of those definitions
// as reaching.

// typedef PList<DefinitionPoint> DefPoints;
typedef DefinitionPoint DefPoints;
typedef std::map<const DefinitionItem*, DefPoints> ReachingDefsMap;

class ReachingDefs;
typedef IntrusivePtr<ReachingDefs> RD_ptr;

inline RD_ptr make_new_RD_ptr() { return make_intrusive<ReachingDefs>(); }

class ReachingDefs : public BroObj {
public:
	void AddRDs(const RD_ptr& rd)
		{
		auto& rd_m = rd->RDMap();

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

	RD_ptr Intersect(const RD_ptr& r) const;
	RD_ptr Union(const RD_ptr& r) const;

	void Dump() const;

	int Size() const	{ return rd_map.size(); }

protected:
	bool HasPair(const DefinitionItem* di, DefinitionPoint dp) const
		{
		auto l = rd_map.find(di);
		return l != rd_map.end() && l->second.SameAs(dp);
		}

	const ReachingDefsMap& RDMap() const	{ return rd_map; }

	void PrintRD(const DefinitionItem* di, const DefinitionPoint& dp) const;

	ReachingDefsMap rd_map;
};

// Maps script locations (which are represented by their underlying BroObj
// pointers) to the reaching definitions for that particular point.
typedef std::map<const BroObj*, RD_ptr> AnalyInfo;

// Reaching definitions associated with a collection of BroObj's.
class ReachingDefSet : public BroObj {
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

		return RDs->second->HasDI(di);
		}

	RD_ptr RDsIfAny(const BroObj* o) const
		{
		if ( o == nullptr )
			return nullptr;

		auto rd = a_i->find(o);
		if ( rd != a_i->end() )
			return rd->second;
		else
			return nullptr;
		}

	// Creates a new RDset if none exists.
	RD_ptr FindRDs(const BroObj* o) const
		{
		if ( o == nullptr )
			return make_new_RD_ptr();

		auto rd = a_i->find(o);
		if ( rd != a_i->end() )
			return rd->second;
		else
			return make_new_RD_ptr();
		}

	void AddRDs(const BroObj* o, const RD_ptr& rd)
		{
		if ( HasRDs(o) )
			MergeRDs(o, rd);
		else
			a_i->insert(AnalyInfo::value_type(o, rd));
		}

protected:
	void MergeRDs(const BroObj* o, const RD_ptr& rd)
		{
		auto curr_rds = a_i->find(o)->second;
		curr_rds->AddRDs(rd);
		}

	AnalyInfo* a_i;
	DefItemMap& item_map;
};
