// See the file "COPYING" in the main distribution directory for copyright.

// Run-time support for initializing C++-compiled scripts.

#pragma once

#include "zeek/Val.h"
#include "zeek/script_opt/CPP/Attrs.h"
#include "zeek/script_opt/CPP/Func.h"

namespace zeek
	{

using FuncValPtr = IntrusivePtr<zeek::FuncVal>;

namespace detail
	{

// A version of TableType that allows us to first build a "stub" and
// then fill in its actual index & yield later - necessary for dealing
// with recursive types.
class CPPTableType : public TableType
	{
public:
	CPPTableType() : TableType(nullptr, nullptr){};

	void SetIndexAndYield(TypeListPtr ind, TypePtr yield)
		{
		ind = std::move(indices);
		yield_type = std::move(yield);
		}
	};

// An initialization hook for a collection of compiled-to-C++ functions
// (the result of a single invocation of the compiler on a set of scripts).
using CPP_init_func = void (*)();

// Tracks the initialization hooks for different compilation runs.
extern std::vector<CPP_init_func> CPP_init_funcs;

// Registers the given global type, if not already present.
extern void register_type__CPP(TypePtr t, const std::string& name);

// Registers the given compiled function body as associated with the
// given priority and hash.  "events" is a list of event handlers
// relevant for the function body, which should be registered if the
// function body is going to be used.
extern void register_body__CPP(CPPStmtPtr body, int priority, p_hash_type hash,
                               std::vector<std::string> events, void (*finish_init)());

// Same but for standalone function bodies.
extern void register_standalone_body__CPP(CPPStmtPtr body, int priority, p_hash_type hash,
                                          std::vector<std::string> events, void (*finish_init)());

// Registers a lambda body as associated with the given hash.  Includes
// the name of the lambda (so it can be made available as a quasi-global
// identifier), its type, and whether it needs captures.
extern void register_lambda__CPP(CPPStmtPtr body, p_hash_type hash, const char* name, TypePtr t,
                                 bool has_captures);

// Registers a callback for activating a set of scripts associated with
// the given hash.
extern void register_scripts__CPP(p_hash_type h, void (*callback)());

// Activates the function/event handler/hook with the given name and in
// the given module, using (at least) the bodies associated with the
// given hashes.  Creates the identifier using the given module and
// export setting if it doesn't already exist.
extern void activate_bodies__CPP(const char* fn, const char* module, bool exported, TypePtr t,
                                 std::vector<p_hash_type> hashes);

// Looks for a global with the given name.  If not present, creates it
// with the given type and export setting.
extern IDPtr lookup_global__CPP(const char* g, const TypePtr& t, bool exported);

// Looks for a BiF with the given name.  Returns nil if not present.
extern Func* lookup_bif__CPP(const char* bif);

// For the function body associated with the given hash, creates and
// returns an associated FuncVal.  It's a fatal error for the hash
// not to exist, because this function should only be called by compiled
// code that has ensured its existence.
extern FuncValPtr lookup_func__CPP(std::string name, int num_bodies, std::vector<p_hash_type> h,
                                   const TypePtr& t);

// Looks for a global with the given name, generating a run-time error
// if not present.
extern IDPtr find_global__CPP(const char* g);

// Returns the record corresponding to the given name, as long as the
// name is indeed a record type.  Otherwise (or if the name is nil)
// creates a new empty record.
extern RecordTypePtr get_record_type__CPP(const char* record_type_name);

// Returns the "enum" type corresponding to the given name, as long as
// the name is indeed an enum type.  Otherwise, creates a new enum
// type with the given name.
extern EnumTypePtr get_enum_type__CPP(const std::string& enum_type_name);

// Returns an enum value corresponding to the given low-level value 'i'
// in the context of the given enum type 't'.
extern EnumValPtr make_enum__CPP(TypePtr t, zeek_int_t i);

	} // namespace zeek::detail
	} // namespace zeek
