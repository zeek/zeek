// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/script_opt/DefItem.h"
#include "zeek/script_opt/DefPoint.h"
#include "zeek/script_opt/ReachingDefs.h"

namespace zeek::detail
	{

// Class for managing collections of reaching definitions associated
// with AST nodes.
//
// Each node has "pre" RDs reflecting the reaching definitions active
// before the node executes, and "post" RDs reflecting the state after
// executing.
//
// In addition, we track both *minimal* RDs (those guaranteed to exist)
// and *maximal* RDs (those that _could_ exist).
//
// To illustrate both of these notions with an example, consider this
// scripting code:
//
//	local x = 5;
//	if ( predicate() )
//		x = 9;
//	foobar();
//
// The "x = 5" node has empty pre-RDs, and minimal and maximal post-RDs
// of {x = 5 <node-at-line-1>}.  The "if" node and its interior call
// to predicate() both inherit those post-RDs as their pre-RDs, and
// these are also the post-RDs for predicate().
//
// The assignment "x = 9" inherits those post-RDs as its pre-RDs.
// When it executes, has leaves both minimal and maximal post-RDs
// of { x = 9 <node-at-line-3> }.
//
// The post-RDs for the "if" statement (and thus the pre-RDs for the foobar()
// call) have a minimal set of { x = SOMETHING }, and a maximal set of
// { x = 5 <node-at-line-1>, x = 9 <node-at-line-3> }.  The minimal set
// here captures the notion that "x is definitely assigned to a value
// at this point, but it's uncertain just what that value is".

class DefSetsMgr
	{
public:
	DefSetsMgr();

	// Returns the minimal or maximal pre-RDs associated with a given node.
	RDPtr GetPreMinRDs(const Obj* o) const { return GetRDs(pre_min_defs, o); }
	RDPtr GetPreMaxRDs(const Obj* o) const { return GetRDs(pre_max_defs, o); }

	// Same, but for post-RDs.
	RDPtr GetPostMinRDs(const Obj* o) const
		{
		if ( HasPostMinRDs(o) )
			return GetRDs(post_min_defs, o);
		else
			return GetPreMinRDs(o);
		}
	RDPtr GetPostMaxRDs(const Obj* o) const
		{
		if ( HasPostMaxRDs(o) )
			return GetRDs(post_max_defs, o);
		else
			return GetPreMaxRDs(o);
		}

	// Initialize a node's pre-RDs to be empty.
	void SetEmptyPre(const Obj* o)
		{
		auto empty_rds = make_intrusive<ReachingDefs>();
		SetPreMinRDs(o, empty_rds);
		SetPreMaxRDs(o, empty_rds);
		}

	// Inherit a node's pre-RDs from those of another node.
	void SetPreFromPre(const Obj* target, const Obj* source)
		{
		SetPreMinRDs(target, GetPreMinRDs(source));
		SetPreMaxRDs(target, GetPreMaxRDs(source));
		}

	// Inherit a node's pre-RDs from the post-RDs of another node.
	void SetPreFromPost(const Obj* target, const Obj* source)
		{
		SetPreMinRDs(target, GetPostMinRDs(source));
		SetPreMaxRDs(target, GetPostMaxRDs(source));
		}

	// Set the post-RDs for a given node to the given min/max values.
	void SetPostRDs(const Obj* o, RDPtr min_rd, RDPtr max_rd)
		{
		SetPostMinRDs(o, std::move(min_rd));
		SetPostMaxRDs(o, std::move(max_rd));
		}

	// Propagate the node's pre-RDs to also be its post-RDs.
	void SetPostFromPre(const Obj* o)
		{
		SetPostMinRDs(o, GetPreMinRDs(o));
		SetPostMaxRDs(o, GetPreMaxRDs(o));
		}

	// Inherit a node's post-RDs from another node's pre-RDs.
	void SetPostFromPre(const Obj* target, const Obj* source)
		{
		SetPostMinRDs(target, GetPreMinRDs(source));
		SetPostMaxRDs(target, GetPreMaxRDs(source));
		}

	// Inherit a node's post-RDs from another node's post-RDs.
	void SetPostFromPost(const Obj* target, const Obj* source)
		{
		SetPostMinRDs(target, GetPostMinRDs(source));
		SetPostMaxRDs(target, GetPostMaxRDs(source));
		}

	// Fine-grained control for setting RDs.
	void SetPreMinRDs(const Obj* o, RDPtr rd) { pre_min_defs->SetRDs(o, std::move(rd)); }
	void SetPreMaxRDs(const Obj* o, RDPtr rd) { pre_max_defs->SetRDs(o, std::move(rd)); }

	void SetPostMinRDs(const Obj* o, RDPtr rd) { post_min_defs->SetRDs(o, std::move(rd)); }
	void SetPostMaxRDs(const Obj* o, RDPtr rd) { post_max_defs->SetRDs(o, std::move(rd)); }

	// Used for confluence: add a set of RDs into those already
	// associated with a node's pre-RDs / post-RDs.  Only applies
	// to maximal RDs.
	void MergeIntoPre(const Obj* o, const RDPtr& rds) { pre_max_defs->AddRDs(o, rds); }
	void MergeIntoPost(const Obj* o, const RDPtr& rds) { post_max_defs->AddRDs(o, rds); }

	// The same, but merging a node's own maximal post-RDs into
	// its maximal pre-RDs.
	void MergePostIntoPre(const Obj* o) { MergeIntoPre(o, GetPostMaxRDs(o)); }

	// The following predicates look up whether a given node exists
	// in the given pre/post minimal/maximal RDs.
	bool HasPreMinRDs(const Obj* o) const { return pre_min_defs && pre_min_defs->HasRDs(o); }
	bool HasPreMaxRDs(const Obj* o) const { return pre_max_defs && pre_max_defs->HasRDs(o); }

	bool HasPostMinRDs(const Obj* o) const { return post_min_defs && post_min_defs->HasRDs(o); }
	bool HasPostMaxRDs(const Obj* o) const { return post_max_defs && post_max_defs->HasRDs(o); }

	// True if the given node has a minimal pre-RD associated
	// with the given identifier.
	bool HasPreMinRD(const Obj* o, const ID* id) const
		{
		return pre_min_defs && pre_min_defs->HasRD(o, id);
		}

	// True if at the given node, there's a single *unambiguous*
	// pre RD for the given identifier.
	bool HasSinglePreMinRD(const Obj* o, const ID* id) const
		{
		return pre_min_defs && pre_min_defs->HasSingleRD(o, id);
		}

	// Methods for creating new pre/post RDs.  If min_only is true,
	// then only done for minimal RDs.
	void CreatePreDef(std::shared_ptr<DefinitionItem> di, DefinitionPoint dp, bool min_only)
		{
		CreateDef(std::move(di), dp, true, min_only);
		}
	void CreatePostDef(const ID* id, DefinitionPoint dp, bool min_only);
	void CreatePostDef(std::shared_ptr<DefinitionItem> di, DefinitionPoint dp, bool min_only);

	std::shared_ptr<DefinitionItem> GetExprDI(const Expr* e) { return item_map.GetExprDI(e); }
	std::shared_ptr<DefinitionItem> GetID_DI(const ID* id) { return item_map.GetID_DI(id); }
	const DefinitionItem* GetConstID_DI(const ID* id) const { return item_map.GetConstID_DI(id); }
	const DefinitionItem* GetConstID_DI(const DefinitionItem* di, const char* field_name) const
		{
		return item_map.GetConstID_DI(di, field_name);
		}

private:
	void CreateDef(std::shared_ptr<DefinitionItem> di, DefinitionPoint dp, bool is_pre,
	               bool min_only);

	RDPtr GetRDs(const RDSetPtr& defs, const Obj* o) const { return defs->FindRDs(o); }

	// Mappings of minimal reaching defs pre- and post- execution
	// of the given node.
	RDSetPtr pre_min_defs;
	RDSetPtr post_min_defs;

	// Mappings of maximal reaching defs pre- and post- execution
	// of the given node.
	RDSetPtr pre_max_defs;
	RDSetPtr post_max_defs;

	DefItemMap item_map;
	};

	} // zeek::detail
