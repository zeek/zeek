// See the file "COPYING" in the main distribution directory for copyright.

#include "DefSetsMgr.h"


DefSetsMgr::DefSetsMgr()
	{
	pre_min_defs = make_intrusive<ReachingDefSet>(item_map);
	post_min_defs = make_intrusive<ReachingDefSet>(item_map);

	pre_max_defs = make_intrusive<ReachingDefSet>(item_map);
	post_max_defs = make_intrusive<ReachingDefSet>(item_map);
	}


void DefSetsMgr::CreatePostDef(const ID* id, DefinitionPoint dp, bool min_only)
	{
	auto di = item_map.GetIDReachingDef(id);
	CreatePostDef(di, dp, min_only);
	}

void DefSetsMgr::CreatePostDef(DefinitionItem* di, DefinitionPoint dp,
				bool min_only)
	{
	auto where = dp.OpaqueVal();

	if ( ! post_min_defs->HasRDs(where) )
		{
		// We haven't yet started creating post RDs for this
		// statement/expression, so create them.
		auto pre = GetPreMinRDs(where);
		SetPostFromPre(where);
		}

	if ( ! min_only && ! post_max_defs->HasRDs(where) )
		{
		auto pre = GetPreMaxRDs(where);
		SetPostFromPre(where);
		}

	CreateDef(di, dp, false, min_only);
	}

void DefSetsMgr::CreateDef(DefinitionItem* di, DefinitionPoint dp,
				bool is_pre, bool min_only)
	{
	auto where = dp.OpaqueVal();

	IntrusivePtr<ReachingDefSet>& min_defs =
		is_pre ? pre_min_defs : post_min_defs;

	min_defs->AddOrReplace(where, di, dp);

	if ( min_only )
		return;

	IntrusivePtr<ReachingDefSet>& max_defs =
		is_pre ? pre_max_defs : post_max_defs;

	max_defs->AddOrReplace(where, di, dp);
	}
