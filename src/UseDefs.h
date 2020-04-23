// See the file "COPYING" in the main distribution directory for copyright.

#include "IntrusivePtr.h"
#include "Obj.h"

#include <vector>
#include <unordered_map>
#include <unordered_set>

// UseDefs track which variables (identifiers) are used at or subsequent
// to a given (reduced) Statement.  They allow us to determine unproductive
// variable assignments (both to warn the user, and to prune temporaries)
// and also access to globals (so we know which ones need to be synchronized
// across function calls).

class Expr;
class Stmt;
class ID;

typedef std::unordered_set<const ID*> use_def_set;

class UseDefSet : public BroObj {
public:
	UseDefSet() : BroObj()	{ }

	void Replicate(const IntrusivePtr<UseDefSet>& from)
		{
		use_defs = from->use_defs;
		}

	bool HasID(const ID* id)
		{ return use_defs.find(id) != use_defs.end(); }

	void Add(const ID* id)		{ use_defs.insert(id); }
	void Remove(const ID* id)	{ use_defs.erase(id); }

	const use_def_set IterateOver() const	{ return use_defs; }

protected:
	std::unordered_set<const ID*> use_defs;
};

typedef IntrusivePtr<UseDefSet> UDs;

class UseDefs {
public:
	~UseDefs();

	void Analyze(const Stmt* s);

	// Note, can return nullptr if there are no usages at all.
	UDs GetUsage(const Stmt* s) const	{ return FindUsage(s); }

	void FindUnused();

	void Dump();

protected:
	// Propagates use-defs (backward) across statement s,
	// given its successor's UDs.
	//
	// succ_stmt is the successor statement to this statement.
	// We only care about it for potential assignment statements,
	// (see the "successor" map below).
	UDs PropagateUDs(const Stmt* s, UDs succ_UDs, const Stmt* succ_stmt);

	UDs FindUsage(const Stmt* s) const;

	// Returns a new use-def corresponding to the variables
	// referenced in e.
	UDs ExprUDs(const Expr* e);

	// Helper method that adds in an expression's use-defs (if any)
	// to an existing set of UDs.
	void AddInExprUDs(UDs uds, const Expr* e);

	// Add an ID into an existing set of UDs.
	void AddID(UDs uds, const ID* id);

	// Returns a new use-def corresonding to given one but
	// with the definition of "id" removed.
	UDs RemoveID(const ID* id, const UDs& uds);

	// Similar, but updates the UDs in place.
	void RemoveUDFrom(UDs uds, const ID* id);

	// Adds in the additional UDs to the main UDs.  Always
	// creates a new use_def and updates main_UDs to point to
	// it, deleting the previous value of main_UDs.
	void FoldInUDs(UDs main_UDs, const UDs& u1, const UDs& u2 = nullptr);

	// Adds in the given UDs to those already associated with s.
	void UpdateUDs(const Stmt* s, const UDs& uds);

	// Returns a new use-def corresponding to the union of 2 or 3 UDs.
	UDs UD_Union(const UDs& u1, const UDs& u2, const UDs& u3 = nullptr);

	// The given statement uses a (shallow) copy of the given UDs.
	UDs CopyUDs(const Stmt* s, const UDs& uds);

	// Sets the given statement's UDs to a new UD set corresponding
	// to the union of the given UDs and those associated with the 
	// given expression.
	UDs CreateExprUDs(const Stmt* s, const Expr* e, const UDs& uds);

	// The given statement takes ownership of the given UDs.
	UDs CreateUDs(const Stmt* s, UDs uds);

	// Note, the value in this could be nullptr.
	std::unordered_map<const Stmt*, UDs> use_defs_map;

	// The following stores statements whose use-defs are
	// currently copies of some other statement's use-defs.
	std::unordered_set<const Stmt*> UDs_are_copies;

	// Track the statements we've processed.  This lets us dump
	// things out in order, even though the main map is unordered.
	std::vector<const Stmt*> stmts;

	// For a given assignment statement, maps it to its successor
	// (the statement that will execute after it).  We need this
	// because we track UDs present at the *beginning* of
	// a statement, not at its end; those at the end are
	// the same as those at the beginning of the successor.
	std::unordered_map<const Stmt*, const Stmt*> successor;
};
