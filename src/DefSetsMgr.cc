// See the file "COPYING" in the main distribution directory for copyright.

#include "DefSetsMgr.h"


DefSetsMgr::DefSetsMgr()
	{
	pre_min_defs = make_intrusive<ReachingDefSet>(item_map);
	post_min_defs = make_intrusive<ReachingDefSet>(item_map);

	pre_max_defs = make_intrusive<ReachingDefSet>(item_map);
	post_max_defs = make_intrusive<ReachingDefSet>(item_map);
	}


void DefSetsMgr::CreatePreDef(DefinitionItem* di, DefinitionPoint dp)
	{
	CreateDef(di, dp, true);
	}

void DefSetsMgr::CreatePostDef(const ID* id, DefinitionPoint dp)
	{
	auto di = item_map.GetIDReachingDef(id);
	CreatePostDef(di, dp);
	}

void DefSetsMgr::CreatePostDef(DefinitionItem* di, DefinitionPoint dp)
	{
	auto where = dp.OpaqueVal();

	if ( ! post_min_defs->HasRDs(where) )
		{
		// We haven't yet started creating post RDs for this
		// statement/expression, so create them.
		auto pre = GetPreMinRDs(where);
		SetPostFromPre(where);
		}

	CreateDef(di, dp, false);
	}

void DefSetsMgr::CreateDef(DefinitionItem* di, DefinitionPoint dp, bool is_pre)
	{
	auto where = dp.OpaqueVal();

	IntrusivePtr<ReachingDefSet>& defs =
		is_pre ? pre_min_defs : post_min_defs;

	defs->AddOrReplace(where, di, dp);
	}
