// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ccl_h
#define ccl_h

#include "List.h"

declare(List,ptr_compat_int);
typedef List(ptr_compat_int) int_list;

class CCL {
public:
	CCL();
	~CCL();

	void Add(int sym);
	void Negate();
	int IsNegated()		{ return negated; }
	int Index()		{ return index; }

	void Sort();

	int_list* Syms()	{ return syms; }

	void ReplaceSyms(int_list* new_syms)
				{ delete syms; syms = new_syms; }

	unsigned int MemoryAllocation() const
		{ return padded_sizeof(*this) + syms->MemoryAllocation(); }

protected:
	int_list* syms;
	int negated;
	int index;
};

#endif
