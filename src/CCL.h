// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <vector>

namespace zeek::detail {

using int_list = std::vector<std::intptr_t>;

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

} // namespace zeek::detail
