// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "util.h" // for ptr_compat_int

#include <vector>

typedef std::vector<ptr_compat_int> int_list;

class CCL {
public:
	CCL();
	~CCL();

	void Add(int sym);
	void Negate();
	bool IsNegated()		{ return negated != 0; }
	int Index()		{ return index; }

	void Sort();

	int_list* Syms()	{ return syms; }

	void ReplaceSyms(int_list* new_syms)
				{ delete syms; syms = new_syms; }

	unsigned int MemoryAllocation() const;

protected:
	int_list* syms;
	int negated;
	int index;
};
