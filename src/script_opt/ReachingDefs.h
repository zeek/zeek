// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/script_opt/DefItem.h"


namespace zeek::detail {


// Maps a DefinitionItem (i.e., a variable or a record field within a
// DefinitionItem) to a list of all the points where the item is defined.
//
// Those points are specific to a given location in a script (see
// AnalyInfo below).  For example, right after an assignment to a variable,
// it will have exactly one associated point (the assignment).  But at
// other points there can be more than one reaching definition; for example,
// a variable defined in both branches of an if-else will cause the location
// in the script after the if-else statement to have both of those definitions
// as (maximally) reaching.

typedef List<DefinitionPoint> DefPoints;
typedef std::unordered_map<const DefinitionItem*, std::unique_ptr<DefPoints>> ReachingDefsMap;


// The ReachingDefs class tracks all of the RDs associated with a given
// AST node.  Often these are the same as for the node's predecessor, so
// the class allows for either have a distinct set of RDs or instead
// pointing to the predecessor's RDs.

class ReachingDefs;
class ReachingDefSet;
using RDPtr = IntrusivePtr<ReachingDefs>;
using RDSetPtr = IntrusivePtr<ReachingDefSet>;

class ReachingDefs : public Obj {
public:
	// Create a new object from scratch.
	ReachingDefs();

	// Create a new object, using the RDs from another object.
	ReachingDefs(RDPtr rd);

	// Add in all the definition points from rd into our set, if
	// we don't already have them.
	void AddRDs(const RDPtr& rd)	{ AddRDs(rd->RDMap()); }

	// Add in a single definition pair, creating the entry for
	// the item if necessary.
	void AddRD(const DefinitionItem* di, const DefinitionPoint& dp);

	// Add a single definition pair, if missing.  If present,
	// replace everything currently associated with new definition.
	void AddOrFullyReplace(const DefinitionItem* di,
				const DefinitionPoint& dp);

	// True if the given definition item is present in our RDs.
	bool HasDI(const DefinitionItem* di) const
		{
		const auto& map = RDMap();
		return map->find(di) != map->end();
		}

	// For the given definition item, returns all of its definition
	// points at our location in the AST.
	DefPoints* GetDefPoints(const DefinitionItem* di)
		{
		const auto& map = RDMap();
		auto dps = map->find(di);
		return dps == map->end() ? nullptr : dps->second.get();
		}

	// Returns true if two sets of definition points are equivalent,
	// *including ordering*.
	bool SameDefPoints(const DefPoints* dp1, const DefPoints* dp2) const
		{
		if ( ! dp1 || ! dp2 )
			return ! dp1 && ! dp2;

		if ( dp1->length() != dp2->length() )
			return false;

		for ( auto i = 0; i < dp1->length(); ++i )
			if ( ! (*dp1)[i].SameAs((*dp2)[i]) )
				return false;

		return true;
		}

	// Return a new object representing the intersection/union of
	// this object's RDs and those of another.
	RDPtr Intersect(const RDPtr& r) const;
	RDPtr Union(const RDPtr& r) const;

	// The following intersects this RD with another, but for
	// DefinitionItem's that have different DefPoints, rather than
	// just fully omitting them (which is what Intersect() will do),
	// creates a joint entry with a special DefinitionPoint
	// corresponding to "multiple definitions".  This allows
	// minimal RDs to capture the notions (1) "yes, that value will
	// be defined at this point", but also (2) "however, we can't
	// rely on which definition reaches".
	//
	// We also do this for items *not* present in r.  The reason is
	// that this method is only called (1) when we know that the items
	// in r have control flow to di, and (2) for "this" being minimal
	// RDs that were present going into the block that resulted in r.
	// Thus, those minimal values will always be present at di; they
	// might not be in r due to the way that r is computed.  (For
	// example, computing them correctly for "for" loop bodies is
	// messy, and irrevant in terms of actually having the correct
	// values for them.)
	RDPtr IntersectWithConsolidation(const RDPtr& r,
					const DefinitionPoint& di) const;

	int Size() const	{ return RDMap()->size(); }

	// Print out the RDs, for debugging purposes.
	void Dump() const;
	void DumpMap(const std::shared_ptr<ReachingDefsMap>& map) const;

protected:
	// True if our RDs include the given definition item, defined at
	// the given definition point.
	bool HasPair(const DefinitionItem* di, const DefinitionPoint& dp) const;

	DefPoints* FindItem(const DefinitionItem* di) const;

	bool HasPoint(const DefinitionPoint&, const DefPoints& dps) const;

	// Adds in the given RDs if we don't already have them.
	void AddRDs(const std::shared_ptr<ReachingDefsMap>& rd_m);

	const std::shared_ptr<ReachingDefsMap>& RDMap() const
		{ return my_rd_map ? my_rd_map : const_rd_map; }

	// If we don't already have our own map, copy the one we're using
	// so that we then do.
	void CopyMapIfNeeded()
		{ if ( ! my_rd_map ) CopyMap(); }
	void CopyMap();

	void PrintRD(const DefinitionItem* di, const DefPoints* dp) const;
	void PrintRD(const DefinitionItem* di, const DefinitionPoint& dp) const;

	// If my_rd_map is non-nil, then we use that map.  Otherwise,
	// we use the map that const_rd_map points to.  The "const" in
	// the latter's name is a reminder to not make any changes to
	// that map.
	std::shared_ptr<ReachingDefsMap> my_rd_map;
	std::shared_ptr<ReachingDefsMap> const_rd_map;
};


// Maps script locations (which are represented by their underlying Obj
// pointers) to the reaching definitions for that particular point.
//
// In spirit, the inverse of ReachingDefsMap.
typedef std::unordered_map<const Obj*, RDPtr> AnalyInfo;


// Reaching definitions associated with a collection of Obj's.
class ReachingDefSet : public Obj {
public:
	ReachingDefSet(DefItemMap& _item_map) : item_map(_item_map)
		{ }

	// Whether in our collection we have RDs associated with the
	// given AST node.
	bool HasRDs(const Obj* o) const	{ return a_i.count(o) > 0; }

	// Whether in our collection we have RDs associated with the
	// given variable.
	bool HasRD(const Obj* o, const ID* id) const
		{ return HasRD(o, item_map.GetConstID_DI(id)); }

	// Whether the given variable has a single = unambiguous RD
	// at the given AST node.
	bool HasSingleRD(const Obj* o, const ID* id) const
		{
		auto RDs = a_i.find(o);
		if ( RDs == a_i.end() )
			return false;

		auto di = item_map.GetConstID_DI(id);
		auto dps = RDs->second->GetDefPoints(di);

		if ( ! dps || dps->length() != 1 )
			return false;

		return (*dps)[0].Tag() != NO_DEF_POINT;
		}

	// Whether the given definition item has an RD at the given
	// AST node.
	bool HasRD(const Obj* o, const DefinitionItem* di) const
		{
		auto RDs = a_i.find(o);
		if ( RDs == a_i.end() )
			return false;

		return RDs->second->HasDI(di);
		}

	// Returns the RDs associated with a given AST node, if any.
	// If none are, returns an empty ReachingDef object.
	const RDPtr& FindRDs(const Obj* o) const;

	// Associates the given RDs with the given AST node.
	void SetRDs(const Obj* o, RDPtr rd)
		{
		auto new_rd = make_intrusive<ReachingDefs>(std::move(rd));
		a_i[o] = new_rd;
		}

	// If the given di is new, add this definition.  If it
	// already exists, replace *all* of its reaching definitions
	// with this new one.
	void AddOrReplace(const Obj* o, const DefinitionItem* di,
				const DefinitionPoint& dp);

	// Add the given RDs to those associated with the AST node 'o'.
	void AddRDs(const Obj* o, const RDPtr& rd)
		{
		if ( HasRDs(o) )
			MergeRDs(o, rd);
		else
			a_i[o] = rd;
		}

protected:
	// Merge in the given RDs with those associated with o's.
	//
	// The caller needs to ensure that we're already tracking the
	// RDs of 'o'.
	void MergeRDs(const Obj* o, const RDPtr& rd)
		{
		auto curr_rds = a_i.find(o)->second;
		curr_rds->AddRDs(rd);
		}

	AnalyInfo a_i;
	DefItemMap& item_map;
};


} // zeek::detail
