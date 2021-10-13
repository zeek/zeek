// See the file "COPYING" in the main distribution directory for copyright.

// C++ compiler support class for managing information about compiled
// objects across compilations.  The objects are identified via hashes,
// hence the term "hash manager".  Objects can exist in different scopes.
// The information mapping hashes to objects and scopes is tracked
// across multiple compilations using intermediary file(s).

#pragma once

#include <stdio.h>

#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail
	{

class CPPHashManager
	{
public:
	// Create a hash manager that uses the given name for
	// referring to hash file(s).  It's a "base" rather than
	// a full name in case the manager winds up managing multiple
	// distinct files (not currently the case).
	//
	// If "append" is true then new hashes will be added to the
	// end of the file (and the hash file will be locked, to prevent
	// overlapping updates from concurrent compilation/appends).
	// Otherwise, the file will be generated afresh.
	CPPHashManager(const char* hash_name_base, bool append);
	~CPPHashManager();

	bool IsAppend() const { return append; }

	// True if the given hash has already been generated.
	bool HasHash(p_hash_type h) const { return previously_compiled.count(h) > 0; }

	// The internal (C++) name of a previously compiled function,
	// as identified by its hash.
	const std::string& FuncBodyName(p_hash_type h) { return previously_compiled[h]; }

	// Whether the given global has already been generated;
	// and, if so, the hashes of its type and initialization
	// value (used for consistency checking).  Here the name
	// is that used at the script level.
	bool HasGlobal(const std::string& gl) const { return gl_type_hashes.count(gl) > 0; }
	p_hash_type GlobalTypeHash(const std::string& gl) { return gl_type_hashes[gl]; }
	p_hash_type GlobalValHash(const std::string& gl) { return gl_val_hashes[gl]; }

	// Whether the given C++ global already exists, and, if so,
	// in what scope.
	bool HasGlobalVar(const std::string& gv) const { return gv_scopes.count(gv) > 0; }
	int GlobalVarScope(const std::string& gv) { return gv_scopes[gv]; }

	// True if the given global corresponds to a record type
	// or an enum type.  Used to suppress complaints about
	// definitional inconsistencies for extensible types.
	bool HasRecordTypeGlobal(const std::string& rt) const
		{
		return record_type_globals.count(rt) > 0;
		}
	bool HasEnumTypeGlobal(const std::string& et) const { return enum_type_globals.count(et) > 0; }

	// Access to the file we're writing hashes to, so that the
	// compiler can add new entries to it.
	FILE* HashFile() const { return hf_w; }

protected:
	// Parses an existing file with hash information.
	void LoadHashes(FILE* f);

	// Helper routines to load lines from  hash file.
	// The first complains if the line isn't present;
	// the second merely indicates whether it was.
	void RequireLine(FILE* f, std::string& line);
	bool GetLine(FILE* f, std::string& line);

	// Generates an error message for a ill-formatted hash file line.
	void BadLine(std::string& line);

	// Tracks previously compiled bodies based on hashes, mapping them
	// to fully qualified (in terms of scoping) C++ names.
	std::unordered_map<p_hash_type, std::string> previously_compiled;

	// Tracks globals that are record or enum types, indexed using
	// script-level names.
	std::unordered_set<std::string> record_type_globals;
	std::unordered_set<std::string> enum_type_globals;

	// Tracks globals seen in previously compiled bodies, mapping
	// script-level names to hashes of their types and their values.
	std::unordered_map<std::string, p_hash_type> gl_type_hashes;
	std::unordered_map<std::string, p_hash_type> gl_val_hashes;

	// Information about globals in terms of their internal variable
	// names, rather than their script-level names.
	std::unordered_map<std::string, int> gv_scopes;

	// Whether we're appending to existing hash file(s), or starting
	// afresh.
	bool append;

	// Base for file names.
	std::string hash_name;

	// Handles for reading from and writing to the hash file.
	// We lock on the first
	FILE* hf_r = nullptr;
	FILE* hf_w = nullptr;
	};

// Maps hashes to indices into C++ globals (like "types_N__CPP"), and
// namespace scopes.
struct CompiledItemPair
	{
	int index;
	int scope;
	};
using VarMapper = std::unordered_map<p_hash_type, CompiledItemPair>;

extern VarMapper compiled_items;

	} // zeek::detail
