// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Stmt.h"
#include "zeek/Expr.h"
#include "zeek/Desc.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/StmtOptInfo.h"


namespace zeek::detail {

const char* trace_ID = nullptr;

IDDefRegion::IDDefRegion(const Stmt* s, bool maybe, int def)
	{
	start_stmt = s->GetOptInfo()->stmt_num;
	block_level = s->GetOptInfo()->block_level;

	Init(maybe, def);
	}

IDDefRegion::IDDefRegion(int stmt_num, int level, bool maybe, int def)
	{
	start_stmt = stmt_num;
	block_level = level;

	Init(maybe, def);
	}

IDDefRegion::IDDefRegion(const Stmt* s, const IDDefRegion& ur)
	{
	start_stmt = s->GetOptInfo()->stmt_num;
	block_level = s->GetOptInfo()->block_level;

	Init(ur.MaybeDefined(), ur.DefinedAfter());
	SetDefExpr(ur.DefExprAfter());
	}

void IDDefRegion::Dump() const
	{
	printf("\t%d->%d (%d): ", start_stmt, end_stmt, block_level);

	if ( defined != NO_DEF )
		printf("%d (%s)", defined, def_expr ? obj_desc(def_expr.get()).c_str() : "<no expr>");
	else if ( maybe_defined )
		printf("?");
	else
		printf("N/A");

	printf("\n");
	}


void IDOptInfo::Clear()
	{
	static bool did_init = false;

	if ( ! did_init )
		{
		trace_ID = getenv("ZEEK_TRACE_ID");
		did_init = true;
		}

	init_exprs.clear();
	usage_regions.clear();
	pending_confluences.clear();
	confluence_stmts.clear();

	tracing = trace_ID && util::streq(trace_ID, my_id->Name());
	}

void IDOptInfo::DefinedAfter(const Stmt* s, const ExprPtr& e,
                             const std::vector<const Stmt*>& conf_blocks,
                             int conf_start)
	{
	if ( tracing )
		printf("ID %s defined at %d: %s\n", trace_ID, s ? s->GetOptInfo()->stmt_num : NO_DEF, s ? obj_desc(s).c_str() : "<entry>");

	if ( ! s )
		{ // This is a definition-upon-entry
		ASSERT(usage_regions.empty());
		usage_regions.emplace_back(0, 0, true, 0);
		if ( tracing )
			DumpBlocks();
		return;
		}

	auto s_oi = s->GetOptInfo();
	auto stmt_num = s_oi->stmt_num;

	if ( usage_regions.empty() )
		{
		// We're seeing this identifier for the first time,
		// so we don't have any context or confluence
		// information for it.  Create its "backstory" region.
		ASSERT(confluence_stmts.empty());
		usage_regions.emplace_back(0, 0, false, NO_DEF);
		}

	// Any pending regions stop prior to this statement.
	EndRegionsAfter(stmt_num - 1, s_oi->block_level);

	// Fill in any missing confluence blocks.
	int b = 0;	// index into our own blocks
	int n = confluence_stmts.size();

	while ( b < n && conf_start < conf_blocks.size() )
		{
		auto outer_block = conf_blocks[conf_start];

		// See if we can find that block.
		for ( ; b < n; ++b )
			if ( confluence_stmts[b] == outer_block )
				break;

		if ( b < n )
			{ // We found it, look for the next one.
			++conf_start;
			++b;
			}
		}

	// Add in the remainder.
	for ( ; conf_start < conf_blocks.size(); ++conf_start )
		StartConfluenceBlock(conf_blocks[conf_start]);

	// Create a new region corresponding to this definition.
	// This needs to come after filling out the confluence
	// blocks, since they'll create their own (earlier) regions.
	usage_regions.emplace_back(s, true, stmt_num);
	usage_regions.back().SetDefExpr(e);

	if ( tracing )
		DumpBlocks();
	}

void IDOptInfo::ReturnAt(const Stmt* s)
	{
	if ( tracing )
		printf("ID %s subject to return %d: %s\n", trace_ID, s->GetOptInfo()->stmt_num, obj_desc(s).c_str());

	// Look for a catch-return that this would branch to.
	for ( int i = confluence_stmts.size() - 1; i >= 0; --i )
		if ( confluence_stmts[i]->Tag() == STMT_CATCH_RETURN )
			{
			BranchBeyond(s, confluence_stmts[i], false);
			if ( tracing )
				DumpBlocks();
			return;
			}

	auto s_oi = s->GetOptInfo();
	EndRegionsAfter(s_oi->stmt_num - 1, s_oi->block_level);

	if ( tracing )
		DumpBlocks();
	}

void IDOptInfo::BranchBackTo(const Stmt* from, const Stmt* to, bool close_all)
	{
	if ( tracing )
		printf("ID %s branching back from %d->%d: %s\n", trace_ID,
		       from->GetOptInfo()->stmt_num,
		       to->GetOptInfo()->stmt_num, obj_desc(from).c_str());

	// The key notion we need to update is whether the regions
	// between from_reg and to_reg still have unique definitions.
	// Confluence due to the branch can only take that away, it
	// can't instill it.  (OTOH, in principle it could update
	// "maybe defined", but not in a way we care about, since we
	// only draw upon that for diagnosing usage errors, and for
	// those the error has already occurred on entry into the loop.)

	auto from_reg = ActiveRegion();
	auto f_oi = from->GetOptInfo();
	auto t_oi = to->GetOptInfo();
	auto t_r_ind = FindRegionBeforeIndex(t_oi->stmt_num);
	auto& t_r = usage_regions[t_r_ind];

	if ( from_reg && from_reg->DefinedAfter() != t_r.DefinedAfter() &&
	     t_r.DefinedAfter() != NO_DEF )
		{
		// They disagree on the definition.  Move the definition
		// point to be the start of the confluence region, and
		// update any blocks inside the region that refer to
		// a pre-"to" definition to instead reflect the confluence
		// region (and remove their definition expressions).
		int new_def = t_oi->stmt_num;

		for ( auto i = t_r_ind; i < usage_regions.size(); ++i )
			{
			auto& ur = usage_regions[i];

			if ( ur.DefinedAfter() < new_def )
				{
				ASSERT(ur.DefinedAfter() != NO_DEF);
				ur.UpdateDefinedAfter(new_def);
				ur.SetDefExpr(nullptr);
				}
			}
		}

	int level = close_all ? t_oi->block_level + 1 : f_oi->block_level;
	EndRegionsAfter(f_oi->stmt_num, level);

	if ( tracing )
		DumpBlocks();
	}

void IDOptInfo::BranchBeyond(const Stmt* end_s, const Stmt* block,
                             bool close_all)
	{
	if ( tracing )
		printf("ID %s branching forward from %d beyond %d: %s\n",
		       trace_ID, end_s->GetOptInfo()->stmt_num,
		       block->GetOptInfo()->stmt_num, obj_desc(end_s).c_str());

	ASSERT(pending_confluences.count(block) > 0);

	auto ar = ActiveRegionIndex();
	if ( ar != NO_DEF )
		pending_confluences[block].insert(ar);

	auto end_oi = end_s->GetOptInfo();
	int level;
	if ( close_all )
		level = block->GetOptInfo()->block_level + 1;
	else
		level = end_oi->block_level;

	EndRegionsAfter(end_oi->stmt_num, level);

	if ( tracing )
		DumpBlocks();
	}

void IDOptInfo::StartConfluenceBlock(const Stmt* s)
	{
	if ( tracing )
		printf("ID %s starting confluence block at %d: %s\n", trace_ID, s->GetOptInfo()->stmt_num, obj_desc(s).c_str());

	auto s_oi = s->GetOptInfo();
	int block_level = s_oi->block_level;

	// End any confluence blocks at this or inner levels.
	for ( auto cs : confluence_stmts )
		{
		ASSERT(cs != s);

		auto cs_level = cs->GetOptInfo()->block_level;

		if ( cs_level >= block_level )
			{
			ASSERT(cs_level == block_level);
			ASSERT(cs == confluence_stmts.back());
			EndRegionsAfter(s_oi->stmt_num - 1, block_level);
			}
		}

	pending_confluences[s] = {};
	confluence_stmts.push_back(s);
	block_has_orig_flow.push_back(s_oi->contains_branch_beyond);

	// Inherit the closest open, outer region, if necessary.
	for ( int i = usage_regions.size() - 1; i >= 0; --i )
		{
		auto& ur = usage_regions[i];

		if ( ur.EndsAfter() == NO_DEF )
			{
			if ( ur.BlockLevel() > block_level )
				{
				// This can happen for regions left over
				// from a previous catch-return, which
				// we haven't closed out yet because we
				// don't track new identifiers beyond
				// outer CRs.  Close the region now.
				ASSERT(s->Tag() == STMT_CATCH_RETURN);
				ur.SetEndsAfter(s_oi->stmt_num - 1);
				continue;
				}

			if ( ur.BlockLevel() < block_level )
				// Didn't find one at our own level,
				// so create on inherited from the
				// outer one.
				usage_regions.emplace_back(s, ur);

			// We now have one at our level that we can use.
			break;
			}
		}

	if ( tracing )
		DumpBlocks();
	}

void IDOptInfo::ConfluenceBlockEndsAfter(const Stmt* s, bool no_orig_flow)
	{
	auto stmt_num = s->GetOptInfo()->stmt_num;

	ASSERT(! confluence_stmts.empty());
	auto cs = confluence_stmts.back();
	auto& pc = pending_confluences[cs];

	// End any active regions.  Those will all have a level >= that
	// of cs, since we're now returning to cs's level.
	int cs_stmt_num = cs->GetOptInfo()->stmt_num;
	int cs_level = cs->GetOptInfo()->block_level;

	if ( tracing )
		printf("ID %s ending (%d) confluence block (%d, level %d) at %d: %s\n", trace_ID, no_orig_flow, cs_stmt_num, cs_level, stmt_num, obj_desc(s).c_str());

	if ( block_has_orig_flow.back() )
		no_orig_flow = false;

	// Compute the state of the definition at the point of confluence:
	// whether it's at least could-be-defined, whether it's definitely
	// defined and if so whether it has a single point of definition.
	bool maybe = false;
	bool defined = true;

	bool did_single_def = false;
	int single_def = NO_DEF;
	ExprPtr single_def_expr;
	bool have_multi_defs = false;

	int num_regions = 0;

	for ( auto i = 0; i < usage_regions.size(); ++i )
		{
		auto& ur = usage_regions[i];

		if ( ur.BlockLevel() < cs_level )
			// Region is not applicable.
			continue;

		if ( ur.EndsAfter() == NO_DEF )
			{ // End this region.
			ur.SetEndsAfter(stmt_num);

			if ( ur.StartsAfter() <= cs_stmt_num && no_orig_flow &&
			     pc.count(i) == 0 )
				// Don't include this region in our assessment.
				continue;
			}

		else if ( ur.EndsAfter() < cs_stmt_num )
			// Irrelevant, didn't extend into confluence region.
			// We test here just to avoid the set lookup in
			// the next test, which presumably will sometimes
			// be a tad expensive.
			continue;

		else if ( pc.count(i) == 0 )
			// This region isn't active, and we're not
			// tracking it for confluence.
			continue;

		++num_regions;

		maybe = maybe || ur.MaybeDefined();

		if ( ur.DefinedAfter() == NO_DEF )
			{
			defined = false;
			continue;
			}

		if ( did_single_def )
			{
			if ( single_def != ur.DefinedAfter() )
				have_multi_defs = true;
			}
		else
			{
			single_def = ur.DefinedAfter();
			single_def_expr = ur.DefExprAfter();
			did_single_def = true;
			}
		}

	if ( num_regions == 0 )
		{ // Nothing survives.
		ASSERT(maybe == false);
		defined = false;
		}

	if ( ! defined )
		{
		single_def = NO_DEF;
		have_multi_defs = false;
		}

	if ( have_multi_defs )
		// Definition reflects confluence point, which comes
		// just after 's'.
		single_def = stmt_num + 1;

	int level = cs->GetOptInfo()->block_level;
	usage_regions.emplace_back(stmt_num, level, maybe, single_def);

	if ( single_def != NO_DEF && ! have_multi_defs )
		usage_regions.back().SetDefExpr(single_def_expr);

	confluence_stmts.pop_back();
	block_has_orig_flow.pop_back();
	pending_confluences.erase(cs);

	if ( tracing )
		DumpBlocks();
	}

bool IDOptInfo::IsPossiblyDefinedBefore(const Stmt* s)
	{
	return IsPossiblyDefinedBefore(s->GetOptInfo()->stmt_num);
	}

bool IDOptInfo::IsDefinedBefore(const Stmt* s)
	{
	return IsDefinedBefore(s->GetOptInfo()->stmt_num);
	}

int IDOptInfo::DefinitionBefore(const Stmt* s)
	{
	return DefinitionBefore(s->GetOptInfo()->stmt_num);
	}

ExprPtr IDOptInfo::DefExprBefore(const Stmt* s)
	{
	return DefExprBefore(s->GetOptInfo()->stmt_num);
	}

bool IDOptInfo::IsPossiblyDefinedBefore(int stmt_num)
	{
	if ( usage_regions.empty() )
		return false;

	return FindRegionBefore(stmt_num).MaybeDefined();
	}

bool IDOptInfo::IsDefinedBefore(int stmt_num)
	{
	if ( usage_regions.empty() )
		return false;

	return FindRegionBefore(stmt_num).DefinedAfter() != NO_DEF;
	}

int IDOptInfo::DefinitionBefore(int stmt_num)
	{
	if ( usage_regions.empty() )
		return NO_DEF;

	return FindRegionBefore(stmt_num).DefinedAfter();
	}

ExprPtr IDOptInfo::DefExprBefore(int stmt_num)
	{
	if ( usage_regions.empty() )
		return nullptr;

	return FindRegionBefore(stmt_num).DefExprAfter();
	}

void IDOptInfo::EndRegionsAfter(int stmt_num, int level)
	{
	for ( int i = usage_regions.size() - 1; i >= 0; --i )
		{
		auto& ur = usage_regions[i];

		if ( ur.BlockLevel() < level )
			return;

		if ( ur.EndsAfter() == NO_DEF )
			ur.SetEndsAfter(stmt_num);
		}
	}

int IDOptInfo::FindRegionBeforeIndex(int stmt_num)
	{
	int region_ind = NO_DEF;
	for ( auto i = 0; i < usage_regions.size(); ++i )
		{
		auto ur = usage_regions[i];

		if ( ur.StartsAfter() >= stmt_num )
			break;

		if ( ur.EndsAfter() == NO_DEF )
			// It's active for everything beyond its start.
			region_ind = i;

		else if ( ur.EndsAfter() >= stmt_num - 1 )
			// It's active at the beginning of the statement of
			// interest.
			region_ind = i;
		}

	ASSERT(region_ind != NO_DEF);
	return region_ind;
	}

int IDOptInfo::ActiveRegionIndex()
	{
	int i;
	for ( i = usage_regions.size() - 1; i >= 0; --i )
		if ( usage_regions[i].EndsAfter() == NO_DEF )
			return i;

	return NO_DEF;
	}

void IDOptInfo::DumpBlocks() const
	{
	for ( auto& ur : usage_regions )
		ur.Dump();

	printf("<end>\n");
	}

} // zeek::detail
