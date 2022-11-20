// See the file "COPYING" in the main distribution directory for copyright.

// C++ compiler helper class that tracks distinct instances of a given key,
// where the key can have any IntrusivePtr type.  The properties of a
// tracker are that it (1) supports a notion that two technically distinct
// keys in fact reflect the same underlying object, (2) provides an
// instance of such keys to consistently serve as their "representative", and
// (3) provides names (suitable for use as C++ variables) for representative
// keys.
//
// Notions of "same" are taken from hash values ala those provided by
// ProfileFunc.

#pragma once

#include "zeek/script_opt/CPP/InitsInfo.h"

namespace zeek::detail
	{

// T is a type that has an IntrusivePtr instantiation.

template <class T> class CPPTracker
	{
public:
	// The base name is used to construct key names.  "single_global",
	// if true, specifies that the names should be constructed as
	// indexes into a single global, rather than as distinct globals.
	CPPTracker(const char* _base_name, bool _single_global)
		: base_name(_base_name), single_global(_single_global)
		{
		}

	// True if the given key has already been entered.
	bool HasKey(const T* key) const { return map.count(key) > 0; }
	bool HasKey(IntrusivePtr<T> key) const { return HasKey(key.get()); }

	// Only adds the key if it's not already present.
	void AddKey(IntrusivePtr<T> key, p_hash_type h);

	void AddInitInfo(const T* rep, std::shared_ptr<CPP_InitInfo> gi) { gi_s[rep] = std::move(gi); }

	// Returns the (C++ variable) name associated with the given key.
	std::string KeyName(const T* key);
	std::string KeyName(IntrusivePtr<T> key) { return KeyName(key.get()); }

	// Returns all of the distinct keys entered into the tracker.
	// A key is "distinct" if it's a representative.
	const std::vector<IntrusivePtr<T>>& DistinctKeys() const { return keys; }

	// For a given key, get its representative.
	const T* GetRep(const T* key)
		{
		ASSERT(HasKey(key));
		return reps[map[key]];
		}
	const T* GetRep(IntrusivePtr<T> key) { return GetRep(key.get()); }

private:
	// Maps keys to internal representations (i.e., hashes).
	std::unordered_map<const T*, p_hash_type> map;

	std::unordered_map<const T*, std::shared_ptr<CPP_InitInfo>> gi_s;

	// Maps internal representations to distinct values.
	std::unordered_map<p_hash_type, int> map2;

	// Tracks the set of distinct keys, to facilitate iterating over them.
	// Each such key also has an entry in map2.
	std::vector<IntrusivePtr<T>> keys;

	// Maps internal representations back to keys.
	std::unordered_map<p_hash_type, const T*> reps;

	// Used to construct key names.
	std::string base_name;

	// Whether to base the names out of a single global, or distinct
	// globals.
	bool single_global;
	};

	} // zeek::detail
