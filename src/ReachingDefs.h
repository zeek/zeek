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

typedef List<DefinitionPoint>* DefPoints;
typedef std::map<const DefinitionItem*, DefPoints> ReachingDefsMap;

class ReachingDefs;
typedef IntrusivePtr<ReachingDefs> RD_ptr;

inline RD_ptr make_new_RD_ptr() { return make_intrusive<ReachingDefs>(); }
inline RD_ptr make_new_RD_ptr(RD_ptr& rd)
	{ return make_intrusive<ReachingDefs>(rd); }

class ReachingDefs : public BroObj {
public:
	ReachingDefs();
	ReachingDefs(RD_ptr& rd);

	~ReachingDefs();

	// Add in all the definition points from rd into our set.
	void AddRDs(const RD_ptr& rd)	{ AddRDs(rd->RDMap()); }

	// Add in a single definition pair, creating the entry for
	// the item if necessary.
	void AddRD(const DefinitionItem* di, const DefinitionPoint& dp);

	// Add a single definition pair if missing.  If present,
	// replace everything currently associated with new definition.
	void AddOrFullyReplace(const DefinitionItem* di,
				const DefinitionPoint& dp);

	bool HasDI(const DefinitionItem* di) const
		{
		auto map = RDMap();
		return map->find(di) != map->end();
		}

	// Return a new object representing the intersection/union of
	// this object's RDs and those of another.
	RD_ptr Intersect(const RD_ptr& r) const;
	RD_ptr Union(const RD_ptr& r) const;

	// The following interesects this RD with another, but for
	// DefinitionItem's that have different DefPoints, rather
	// than just fully omitting them, creates a new entry
	// using the supplied DefinitionPoint.
	RD_ptr IntersectWithConsolidation(const RD_ptr& r,
					const DefinitionPoint& di) const;

	void Dump() const;
	void DumpMap(const ReachingDefsMap* map) const;

	int Size() const	{ return RDMap()->size(); }

protected:
	bool HasPair(const DefinitionItem* di, const DefinitionPoint& dp) const;

	void AddRDs(const ReachingDefsMap* rd_m);

	const ReachingDefsMap* RDMap() const
		{ return my_rd_map ? my_rd_map : const_rd_map->RDMap(); }

	void CopyMapIfNeeded();

	void PrintRD(const DefinitionItem* di, const DefPoints& dp) const;
	void PrintRD(const DefinitionItem* di, const DefinitionPoint& dp) const;

	// If my_rd_map is non-nill, then we use that map.  Otherwise,
	// we use the map that const_rd_map points to.
	RD_ptr const_rd_map;
	ReachingDefsMap* my_rd_map;
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

	// Should only be called if there are already RDs associated with
	// the given object.
	RD_ptr& FindRDs(const BroObj* o) const;

	void SetRDs(const BroObj* o, RD_ptr& rd)
		{
		auto new_rd = make_new_RD_ptr(rd);
		a_i->insert(AnalyInfo::value_type(o, new_rd));
		}

	// If the given di is new, add this definition.  If it
	// already exists, replace *all* of its reaching definitions
	// with this new one.
	void AddOrReplace(const BroObj* o, const DefinitionItem* di,
				const DefinitionPoint& dp);

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
