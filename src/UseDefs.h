// See the file "COPYING" in the main distribution directory for copyright.

#include "IntrusivePtr.h"

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
typedef std::unordered_set<const ID*> use_defs;

class UseDefs {
public:
	~UseDefs();

	void Analyze(const Stmt* s);

	// Note, can return nullptr if there are no usages at all.
	const use_defs* GetUsage(const Stmt* s)
		{ return FindUsage(s); }

protected:
	// Propagates use-defs (backward) across statement s,
	// given its successor's UDs.  May return a shallow
	// copy to the successor UDs, or may have taken ownership
	// for an independent set of UDs.  When calling, the
	// discipline is to assume that whatever's returned
	// is ultimately owned by some statement, and should
	// only be used via copy-on-write.
	use_defs* PropagateUDs(const Stmt* s, use_defs* succ_UDs);

	use_defs* FindUsage(const Stmt* s);

	// Returns a new use-def corresponding to the variables
	// referenced in e.
	use_defs* ExprUDs(const Expr* e);

	// Helper method that adds in an expression's use-defs (if any)
	// to an existing set of UDs.
	void AddInExprUDs(use_defs* uds, const Expr* e);

	// Add an ID into an existing set of UDs.
	void AddID(use_defs* uds, const ID* id);

	// Returns a new use-def corresonding to given one but
	// with the definition of "id" removed.
	use_defs* RemoveID(const ID* id, const use_defs* UDs);

	// Similar, but updates the UDs in place.
	void RemoveUDFrom(use_defs* UDs, const ID* id);

	// Adds in the additional UDs to the main UDs.  Always
	// creates a new use_def and updates main_UDs to point to
	// it, deleting the previous value of main_UDs.
	void FoldInUDs(use_defs*& main_UDs, const use_defs* u1,
			const use_defs* u2 = nullptr);

	// Adds in the given UDs to those already associated with s.
	void UpdateUDs(const Stmt* s, const use_defs* UDs);

	// Returns a new use-def corresponding to the union of 2 or 3 UDs.
	use_defs* UD_Union(const use_defs* u1, const use_defs* u2,
			const use_defs* u3 = nullptr);

	// The given statement uses a (shallow) copy of the given UDs.
	use_defs* CopyUDs(const Stmt* s, use_defs* UDs);

	// Sets the given statement's UDs to a new UD set corresponding
	// to the union of the given UDs and those associated with the 
	// given expression.
	use_defs* CreateExprUDs(const Stmt* s, const Expr* e,
				const use_defs* UDs);

	// The given statement takes ownership of the given UDs.
	use_defs* CreateUDs(const Stmt* s, use_defs* UDs);

	// Note, the value in this could be nullptr.
	std::unordered_map<const Stmt*, use_defs*> use_defs_map;

	// The following stores statements whose use-defs are
	// currently copies of some other statement's use-defs.
	std::unordered_set<const Stmt*> UDs_are_copies;
};
