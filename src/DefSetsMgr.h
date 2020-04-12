// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "DefItem.h"
#include "DefPoint.h"
#include "ReachingDefs.h"


class DefSetsMgr {
public:
	DefSetsMgr();

	RD_ptr& GetPreMinRDs(const BroObj* o) const
		{ return GetRDs(pre_min_defs, o); }
	RD_ptr& GetPreMaxRDs(const BroObj* o) const
		{ return GetRDs(pre_max_defs, o); }

	RD_ptr& GetPostMinRDs(const BroObj* o) const
		{
		if ( HasPostMinRDs(o) )
			return GetRDs(post_min_defs, o);
		else
			return GetPreMinRDs(o);
		}
	RD_ptr& GetPostMaxRDs(const BroObj* o) const
		{
		if ( HasPostMaxRDs(o) )
			return GetRDs(post_max_defs, o);
		else
			return GetPreMaxRDs(o);
		}

	void SetPostRDs(const BroObj* o, RD_ptr& min_rd, RD_ptr& max_rd)
		{
		SetPostMinRDs(o, min_rd);
		SetPostMaxRDs(o, max_rd);
		}

	void SetEmptyPre(const BroObj* o)
		{
		auto empty_rds = make_new_RD_ptr();
		SetPreMinRDs(o, empty_rds);
		SetPreMaxRDs(o, empty_rds);
		empty_rds.release();
		}

	void SetPreFromPre(const BroObj* target, const BroObj* source)
		{
		SetPreMinRDs(target, GetPreMinRDs(source));
		SetPreMaxRDs(target, GetPreMaxRDs(source));
		}

	void SetPreFromPost(const BroObj* target, const BroObj* source)
		{
		SetPreMinRDs(target, GetPostMinRDs(source));
		SetPreMaxRDs(target, GetPostMaxRDs(source));
		}

	void SetPostFromPre(const BroObj* o)
		{
		SetPostMinRDs(o, GetPreMinRDs(o));
		SetPostMaxRDs(o, GetPreMaxRDs(o));
		}

	void SetPostFromPre(const BroObj* target, const BroObj* source)
		{
		SetPostMinRDs(target, GetPreMinRDs(source));
		SetPostMaxRDs(target, GetPreMaxRDs(source));
		}

	void SetPostFromPost(const BroObj* target, const BroObj* source)
		{
		SetPostMinRDs(target, GetPostMinRDs(source));
		SetPostMaxRDs(target, GetPostMaxRDs(source));
		}

	// The following only applies to max RDs.
	void MergePostIntoPre(const BroObj* o)
		{
		// Don't use SetRDs as that overwrites.  We instead
		// want to merge.
		pre_max_defs->AddRDs(o, GetPostMaxRDs(o));
		}


	bool HasPreMinRDs(const BroObj* o) const
		{ return pre_min_defs->HasRDs(o); }
	bool HasPreMaxRDs(const BroObj* o) const
		{ return pre_max_defs->HasRDs(o); }

	bool HasPreMinRD(const BroObj* o, const ID* id) const
		{ return pre_min_defs->HasRD(o, id); }

	bool HasPostMinRDs(const BroObj* o) const
		{ return post_min_defs->HasRDs(o); }
	bool HasPostMaxRDs(const BroObj* o) const
		{ return post_max_defs->HasRDs(o); }

	void CreatePreDef(DefinitionItem* di, DefinitionPoint dp, bool min_only)
		{ CreateDef(di, dp, true, min_only); }
	void CreatePostDef(const ID* id, DefinitionPoint dp, bool min_only);
	void CreatePostDef(DefinitionItem* di, DefinitionPoint dp, bool min_only);

	void CreatePostRDsFromPre(const Stmt* s)
		{
		SetPostMinRDs(s, GetPreMinRDs(s));
		SetPostMaxRDs(s, GetPreMaxRDs(s));
		}
	void CreatePostRDsFromPost(const Stmt* target, const BroObj* source)
		{
		SetPostMinRDs(target, GetPostMinRDs(source));
		SetPostMaxRDs(target, GetPostMaxRDs(source));
		}

	void CreatePostRDs(const Stmt* target, RD_ptr& min_rds, RD_ptr& max_rds)
		{
		SetPostMinRDs(target, min_rds);
		SetPostMaxRDs(target, max_rds);
		}

	void CreateDef(DefinitionItem* di, DefinitionPoint dp,
			bool is_pre, bool min_only);

	DefinitionItem* GetExprReachingDef(Expr* e)
		{ return item_map.GetExprReachingDef(e); }
	DefinitionItem* GetIDReachingDef(const ID* id)
		{ return item_map.GetIDReachingDef(id); }
	const DefinitionItem* GetConstIDReachingDef(const ID* id) const
		{ return item_map.GetConstIDReachingDef(id); }
        const DefinitionItem* GetConstIDReachingDef(const DefinitionItem* di,
						const char* field_name) const
		{ return item_map.GetConstIDReachingDef(di, field_name); }

protected:
	RD_ptr& GetRDs(const IntrusivePtr<ReachingDefSet> defs,
				const BroObj* o) const
		{
		return defs->FindRDs(o);
		}

	void SetPreMinRDs(const BroObj* o, RD_ptr& rd)
		{ pre_min_defs->SetRDs(o, rd); }
	void SetPreMaxRDs(const BroObj* o, RD_ptr& rd)
		{ pre_max_defs->SetRDs(o, rd); }

	void SetPostMinRDs(const BroObj* o, RD_ptr& rd)
		{ post_min_defs->SetRDs(o, rd); }
	void SetPostMaxRDs(const BroObj* o, RD_ptr& rd)
		{ post_max_defs->SetRDs(o, rd); }

	// Mappings of minimal reaching defs pre- and post- execution
	// of the given object.
	IntrusivePtr<ReachingDefSet> pre_min_defs;
	IntrusivePtr<ReachingDefSet> post_min_defs;

	// Mappings of maximal reaching defs pre- and post- execution
	// of the given object.
	IntrusivePtr<ReachingDefSet> pre_max_defs;
	IntrusivePtr<ReachingDefSet> post_max_defs;

	DefItemMap item_map;
};
