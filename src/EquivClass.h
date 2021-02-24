// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <stdio.h>

namespace zeek::detail {

class CCL;

class EquivClass {
public:
	explicit EquivClass(int size);
	~EquivClass();

	void UniqueChar(int sym);
	void CCL_Use(CCL* ccl);

	// All done adding character usage info - generate equivalence
	// classes.  Returns number of classes.
	int BuildECs();

	void ConvertCCL(CCL* ccl);

	bool IsRep(int sym) const		{ return rep[sym] == sym; }
	int EquivRep(int sym) const		{ return rep[sym]; }
	int SymEquivClass(int sym) const	{ return equiv_class[sym]; }
	int* EquivClasses() const		{ return equiv_class; }

	int NumSyms() const	{ return size; }
	int NumClasses() const	{ return num_ecs; }

	void Dump(FILE* f);
	int Size() const;

protected:
	int size;	// size of character set
	int num_ecs;	// size of equivalence classes
	int* fwd;	// forward list of different classes
	int* bck;	// backward list
	int* equiv_class;	// symbol's equivalence class
	int* rep;	// representative for symbol's equivalence class
	int* ccl_flags;
	int ec_nil, no_class, no_rep;
};

} // namespace zeek::detail
