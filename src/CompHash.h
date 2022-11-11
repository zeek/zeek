// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/Func.h"
#include "zeek/Type.h"

namespace zeek
	{

class ListVal;
using ListValPtr = zeek::IntrusivePtr<ListVal>;

	} // namespace zeek

namespace zeek::detail
	{

class HashKey;

class CompositeHash
	{
public:
	explicit CompositeHash(TypeListPtr composite_type);

	// Compute the hash corresponding to the given index val,
	// or nullptr if it fails to typecheck.
	std::unique_ptr<HashKey> MakeHashKey(const Val& v, bool type_check) const;

	// Given a hash key, recover the values used to create it.
	ListValPtr RecoverVals(const HashKey& k) const;

protected:
	bool SingleValHash(HashKey& hk, const Val* v, Type* bt, bool type_check, bool optional,
	                   bool singleton) const;

	// Recovers just one Val of possibly many; called from RecoverVals.
	// Upon return, pval will point to the recovered Val of type t.
	// Returns and updated kp for the next Val.  Calls reporter->InternalError()
	// upon errors, so there is no return value for invalid input.
	bool RecoverOneVal(const HashKey& k, Type* t, ValPtr* pval, bool optional,
	                   bool singleton) const;

	// Compute the size of the composite key.  If v is non-nil then
	// the value is computed for the particular list of values.
	// Returns 0 if the key has an indeterminate size (if v not given),
	// or if v doesn't match the index type (if given).
	bool ReserveKeySize(HashKey& hk, const Val* v, bool type_check, bool calc_static_size) const;

	bool ReserveSingleTypeKeySize(HashKey& hk, Type*, const Val* v, bool type_check, bool optional,
	                              bool calc_static_size, bool singleton) const;

	bool EnsureTypeReserve(HashKey& hk, const Val* v, Type* bt, bool type_check) const;

	// The following are for allowing hashing of function values.
	// These can occur, for example, in sets of predicates that get
	// iterated over.  We use pointers in order to keep storage
	// lower for the common case of these not being needed.
	std::unique_ptr<std::unordered_map<const Func*, uint32_t>> func_to_func_id;
	std::unique_ptr<std::vector<FuncPtr>> func_id_to_func;
	void BuildFuncMappings()
		{
		func_to_func_id = std::make_unique<std::unordered_map<const Func*, uint32_t>>();
		func_id_to_func = std::make_unique<std::vector<FuncPtr>>();
		}

	TypeListPtr type;
	bool is_singleton = false; // if just one type in index
	};

	} // namespace zeek::detail
