// See the file "COPYING" in the main distribution directory for copyright.

// Subclasses of Func and Stmt to support C++-generated code, along
// with tracking of that code to enable hooking into it at run-time.

#pragma once

#include "zeek/Func.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek
	{

namespace detail
	{

// A subclass of Func used for lambdas that the compiler creates for
// complex initializations (expressions used in type attributes).
// The usage is via derivation from this class, rather than direct
// use of it.

class CPPFunc : public Func
	{
public:
	bool IsPure() const override { return is_pure; }

	void Describe(ODesc* d) const override;

protected:
	// Constructor used when deriving subclasses.
	CPPFunc(const char* _name, bool _is_pure)
		{
		name = _name;
		is_pure = _is_pure;
		}

	std::string name;
	bool is_pure;
	};

// A subclass of Stmt used to replace a function/event handler/hook body.

class CPPStmt : public Stmt
	{
public:
	CPPStmt(const char* _name, const char* filename, int line_num);

	const std::string& Name() { return name; }

	// Sets/returns a hash associated with this statement.  A value
	// of 0 means "not set".
	p_hash_type GetHash() const { return hash; }
	void SetHash(p_hash_type h) { hash = h; }

	// The following only get defined by lambda bodies.
	virtual void SetLambdaCaptures(Frame* f) { }
	virtual std::vector<ValPtr> SerializeLambdaCaptures() const { return std::vector<ValPtr>{}; }

	virtual IntrusivePtr<CPPStmt> Clone() { return {NewRef{}, this}; }

protected:
	// This method being called means that the inliner is running
	// on compiled code, which shouldn't happen.
	StmtPtr Duplicate() override
		{
		ASSERT(0);
		return ThisPtr();
		}

	TraversalCode Traverse(TraversalCallback* cb) const override { return TC_CONTINUE; }

	std::string name;
	p_hash_type hash = 0ULL;

	// A pseudo AST "call" node, used to support error localization.
	CallExprPtr ce;
	};

using CPPStmtPtr = IntrusivePtr<CPPStmt>;

// For script-level lambdas, a ScriptFunc subclass that knows how to
// deal with its captures for serialization.  Different from CPPFunc in
// that CPPFunc is for lambdas generated directly by the compiler,
// rather than those explicitly present in scripts.

class CPPLambdaFunc : public ScriptFunc
	{
public:
	CPPLambdaFunc(std::string name, FuncTypePtr ft, CPPStmtPtr l_body);

protected:
	// Methods related to sending lambdas via Broker.
	broker::expected<broker::data> SerializeCaptures() const override;
	void SetCaptures(Frame* f) override;

	FuncPtr DoClone() override;

	CPPStmtPtr l_body;
	};

// Information associated with a given compiled script body: its
// Stmt subclass, priority, and any events that should be registered
// upon instantiating the body.
struct CompiledScript
	{
	CPPStmtPtr body;
	int priority;
	std::vector<std::string> events;
	void (*finish_init_func)();
	};

// Maps hashes to compiled information.
extern std::unordered_map<p_hash_type, CompiledScript> compiled_scripts;

// When using standalone-code, tracks which function bodies have had
// compiled versions added to them.  Needed so that we don't replace
// the body twice, leading to two copies.  Indexed first by the name
// of the function, and then via the hash of the body that has been
// added to it.
extern std::unordered_map<std::string, std::unordered_set<p_hash_type>> added_bodies;

// Maps hashes to standalone script initialization callbacks.
extern std::unordered_map<p_hash_type, void (*)()> standalone_callbacks;

// Callbacks to finalize initialization of standalone compiled scripts.
extern std::vector<void (*)()> standalone_finalizations;

	} // namespace detail

	} // namespace zeek
