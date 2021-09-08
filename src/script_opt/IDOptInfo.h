// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with identifiers to aid script
// optimization.

#pragma once

#include <set>

#include "zeek/IntrusivePtr.h"

namespace zeek::detail {

class Expr;
class Stmt;

using ExprPtr = IntrusivePtr<Expr>;

#define NO_DEF -1

// This class tracks a single region during which an identifier has
// a consistent state of definition, meaning either it's (1) defined
// as of its value after a specific statement, (2) might-or-might-not
// be defined, or (3) definitely not defined.

class IDDefRegion {
public:
	IDDefRegion(const Stmt* s, bool maybe, int def);
	IDDefRegion(int stmt_num, int level, bool maybe, int def);
	IDDefRegion(const Stmt* s, const IDDefRegion& ur);

	void Init(bool maybe, int def)
		{
		if ( def != NO_DEF )
			maybe_defined = true;
		else
			maybe_defined = maybe;

		defined = def;
		}

	// Returns the starting point of the region, i.e., the number
	// of the statement *after* which executing this region begins.
	int StartsAfter() const	{ return start_stmt; }

	// Returns or sets the ending point of the region, i.e., the
	// last statement for which this region applies (including executing
	// that statement).  A value of NO_DEF means that the region
	// continues indefinitely, i.e., we haven't yet encountered its end.
	int EndsAfter() const			{ return end_stmt; }
	void SetEndsAfter(int _end_stmt)	{ end_stmt = _end_stmt; }

	// The confluence nesting level associated with the region.  Other
	// regions that overlap take precedence if they have a higher
	// (= more inner) block level.
	int BlockLevel() const		{ return block_level; }

	// True if in the region the identifer could be defined.
	bool MaybeDefined() const	{ return maybe_defined; }

	// Returns (or sets) the statement after which the identifer is
	// (definitely) defined, or NO_DEF if it doesn't have a definite
	// point of definition.
	int DefinedAfter() const		{ return defined; }
	void UpdateDefinedAfter(int _defined)	{ defined = _defined; }

	// Returns (or sets) the expression used to define the identifier,
	// if any.  Note that an identifier can be definitely defined
	// (i.e., DefinedAfter() returns a statement number, not NO_DEF)
	// but not have an associated expression, if the point-of-definition
	// is the end of a confluence block.
	const ExprPtr& DefExprAfter() const	{ return def_expr; }
	void SetDefExpr(ExprPtr e)		{ def_expr = e; }

	// Used for debugging.
	void Dump() const;

protected:
	// Number of the statement for which this region applies *after*
	// its execution.
	int start_stmt;

	// Number of the statement that this region applies to, *after*
	// its execution.
	int end_stmt = NO_DEF;	// means the region hasn't ended yet

	// Degree of confluence nesting associated with this region.
	int block_level;

	// Identifier could be defined in this region.
	bool maybe_defined;

	// If not NO_DEF, then the statement number of either the identifier's
	// definition, or its confluence point if multiple, differing
	// definitions come together.
	int defined;

	// The expression used to define the identifier in this region.
	// Nil if either it's ambiguous (due to confluence), or the
	// identifier isn't guaranteed to be defined.
	ExprPtr def_expr;
};


// Class tracking optimization information associated with identifiers.

class IDOptInfo {
public:
	IDOptInfo(const ID* id)	{ my_id = id; }

	// Reset all computed information about the identifier.  Used
	// when making a second pass over an AST after optimizing it,
	// to avoid inheriting now-stale information.
	void Clear();

	// Used to track expressions employed when explicitly initializing
	// the identifier.  These are needed by compile-to-C++ script
	// optimization.  They're not used by ZAM optimization.
	void AddInitExpr(ExprPtr init_expr);
	const std::vector<ExprPtr>& GetInitExprs() const
		{ return init_exprs; }

	// Associated constant expression, if any.  This is only set
	// for identifiers that are aliases for a constant (i.e., there
	// are no other assignments to them).
	const ConstExpr* Const() const	{ return const_expr; }

	// The most use of "const" in any single line in the Zeek
	// codebase :-P ... though only by one!
	void SetConst(const ConstExpr* _const) { const_expr = _const; }

	// Whether the identifier is a temporary variable.  Temporaries
	// are guaranteed to have exactly one point of definition.
	bool IsTemp() const	{ return is_temp; }
	void SetTemp()		{ is_temp = true; }

	// Called when the identifier is defined via execution of the
	// given statement, with an assignment to the expression 'e'
	// (only non-nil for simple direct assignments).  "conf_blocks"
	// gives the full set of surrounding confluence statements.
	// It should be processed starting at conf_start (note that
	// conf_blocks may be empty).
	void DefinedAfter(const Stmt* s, const ExprPtr& e,
	                  const std::vector<const Stmt*>& conf_blocks,
	                  int conf_start);

	// Called upon encountering a "return" statement.
	void ReturnAt(const Stmt* s);

	// Called when the current region ends with a backwards branch,
	// possibly across multiple block levels, occurring at "from"
	// and going into the block "to".  If "close_all" is true then
	// any pending regions at a level inner to "to" should be
	// closed; if not, just those at "from"'s level.
	void BranchBackTo(const Stmt* from, const Stmt* to, bool close_all);

	// Called when the current region ends at statement end_s with a
	// forwards branch, possibly across multiple block levels, to
	// the statement that comes right after the execution of "block".
	// See above re "close_all".
	void BranchBeyond(const Stmt* end_s, const Stmt* block, bool close_all);

	// Start tracking a confluence block that begins with the body
	// of s (not s itself).
	void StartConfluenceBlock(const Stmt* s);

	// Finish tracking confluence; s is the last point of execution
	// prior to leaving a block.  If no_orig_flow is true, then
	// the region for 's' itself does not continue to the end of
	// the block.
	void ConfluenceBlockEndsAfter(const Stmt* s, bool no_orig_flow);

	// All of these regard the identifer's state just *prior* to
	// executing the given statement.
	bool IsPossiblyDefinedBefore(const Stmt* s);
	bool IsDefinedBefore(const Stmt* s);
	int DefinitionBefore(const Stmt* s);
	ExprPtr DefExprBefore(const Stmt* s);

	// Same, but using statement numbers.
	bool IsPossiblyDefinedBefore(int stmt_num);
	bool IsDefinedBefore(int stmt_num);
	int DefinitionBefore(int stmt_num);
	ExprPtr DefExprBefore(int stmt_num);

	// The following are used to avoid multiple error messages
	// for use of undefined variables.
	bool DidUndefinedWarning() const
		{ return did_undefined_warning; }
	bool DidPossiblyUndefinedWarning() const
		{ return did_possibly_undefined_warning; }

	void SetDidUndefinedWarning()
		{ did_undefined_warning = true; }
	void SetDidPossiblyUndefinedWarning()
		{ did_possibly_undefined_warning = true; }

private:
	// End any active regions that are at or inner to the given level.
	void EndRegionsAfter(int stmt_num, int level);

	// Find the region that applies *before* executing the given
	// statement.  There should always be such a region.
	IDDefRegion& FindRegionBefore(int stmt_num)
		{ return usage_regions[FindRegionBeforeIndex(stmt_num)]; }
	int FindRegionBeforeIndex(int stmt_num);

	// Return the current "active" region, if any.  The active region
	// is the innermost region that currently has an end of NO_DEF,
	// meaning we have not yet found its end.
	IDDefRegion* ActiveRegion()
		{
		auto ind = ActiveRegionIndex();
		return ind >= 0 ? &usage_regions[ind] : nullptr;
		}
	int ActiveRegionIndex();

	// Used for debugging.
	void DumpBlocks() const;

	// Expressions used to initialize the identifier, for use by
	// the scripts-to-C++ compiler.  We need to track all of them
	// because it's possible that a global value gets created using
	// one of the earlier instances rather than the last one.
	std::vector<ExprPtr> init_exprs;

	// If non-nil, a constant that this identifier always holds
	// once initially defined.
	const ConstExpr* const_expr = nullptr;

	// The different usage regions associated with the identifier.
	// These are constructed such that they're always with non-decreasing
	// starting statements.
	std::vector<IDDefRegion> usage_regions;

	// A type for collecting the indices of usage_regions that will
	// all have confluence together at one point.  Used to track
	// things like "break" statements that jump out of loops or
	// switch confluence regions.
	using ConfluenceSet = std::set<int>;

	// Maps loops/switches/catch-returns to their associated
	// confluence sets.
	std::map<const Stmt*, ConfluenceSet> pending_confluences;

	// A stack of active confluence statements, so we can always find
	// the innermost when ending a confluence block.
	std::vector<const Stmt*> confluence_stmts;

	// Parallel vector that tracks whether, upon creating the
	// confluence block, there had already been observed internal flow
	// going beyond it.  If so, then we can ignore no_orig_flow when
	// ending the block, because in fact there *was* original flow.
	std::vector<bool> block_has_orig_flow;

	// Whether the identifier is a temporary variable.
	bool is_temp = false;

	// Only needed for debugging purposes.
	const ID* my_id;
	bool tracing = false;

	// Track whether we've already generated usage errors.
	bool did_undefined_warning = false;
	bool did_possibly_undefined_warning = false;
};

// If non-nil, then output detailed tracing information when building
// up the usage regions for any identifier with the given name.
extern const char* trace_ID;

} // namespace zeek::detail
