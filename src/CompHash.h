// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/Type.h"
#include "zeek/IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(ListVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(HashKey, zeek::detail);

namespace zeek {
using ListValPtr = zeek::IntrusivePtr<ListVal>;
}

namespace zeek::detail {

class CompositeHash {
public:
	explicit CompositeHash(TypeListPtr composite_type);
	~CompositeHash();

	// Compute the hash corresponding to the given index val,
	// or nullptr if it fails to typecheck.
	std::unique_ptr<HashKey> MakeHashKey(const Val& v, bool type_check) const;

	// Given a hash key, recover the values used to create it.
	ListValPtr RecoverVals(const HashKey& k) const;

	unsigned int MemoryAllocation() const { return padded_sizeof(*this) + util::pad_size(size); }

protected:
	std::unique_ptr<HashKey> ComputeSingletonHash(const Val* v, bool type_check) const;

	// Computes the piece of the hash for Val*, returning the new kp.
	// Used as a helper for ComputeHash in the non-singleton case.
	char* SingleValHash(bool type_check, char* kp, Type* bt, Val* v,
	                    bool optional) const;

	// Recovers just one Val of possibly many; called from RecoverVals.
	// Upon return, pval will point to the recovered Val of type t.
	// Returns and updated kp for the next Val.  Calls reporter->InternalError()
	// upon errors, so there is no return value for invalid input.
	const char* RecoverOneVal(
		const HashKey& k, const char* kp, const char* const k_end,
		Type* t, ValPtr* pval, bool optional) const;

	// Rounds the given pointer up to the nearest multiple of the
	// given size, if not already a multiple.
	const void* Align(const char* ptr, unsigned int size) const;

	// Rounds the given pointer up to the nearest multiple of the
	// given size, padding the skipped region with 0 bytes.
	void* AlignAndPad(char* ptr, unsigned int size) const;

	// Returns offset+size rounded up so it can correctly align data
	// of the given size.
	int SizeAlign(int offset, unsigned int size) const;

	template<class T>
	T* AlignAndPadType(char* ptr) const
		{
		return reinterpret_cast<T*>(AlignAndPad(ptr, sizeof(T)));
		}

	template<class T>
	const T* AlignType(const char* ptr) const
		{
		return reinterpret_cast<const T*>(Align(ptr, sizeof(T)));
		}

	template<class T>
	int SizeAlignType(int offset) const
		{
		return SizeAlign(offset, sizeof(T));
		}

	// Compute the size of the composite key.  If v is non-nil then
	// the value is computed for the particular list of values.
	// Returns 0 if the key has an indeterminant size (if v not given),
	// or if v doesn't match the index type (if given).
	int ComputeKeySize(const Val* v, bool type_check,
	                   bool calc_static_size) const;

	int SingleTypeKeySize(Type*, const Val*,
	                      bool type_check, int sz, bool optional,
	                      bool calc_static_size) const;

	TypeListPtr type;
	char* key;	// space for composite key
	int size;
	bool is_singleton;	// if just one type in index

	// If one type, but not normal "singleton", e.g. record.
	bool is_complex_type;

	InternalTypeTag singleton_tag;
};

} // namespace zeek::detail
