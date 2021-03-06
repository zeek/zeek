// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/CCL.h"

#include <algorithm>

#include "zeek/RE.h"
#include "zeek/DFA.h"

namespace zeek::detail {

CCL::CCL()
	{
	syms = new int_list;
	index = -(rem->InsertCCL(this) + 1);
	negated = 0;
	}

CCL::~CCL()
	{
	delete syms;
	}

void CCL::Negate()
	{
	negated = 1;
	Add(SYM_BOL);
	Add(SYM_EOL);
	}

void CCL::Add(int sym)
	{
	auto sym_p = static_cast<std::intptr_t>(sym);

	// Check to see if the character is already in the ccl.
	for ( auto sym_entry : *syms )
		if ( sym_entry == sym_p )
			return;

	syms->push_back(sym_p);
	}

void CCL::Sort()
	{
	std::sort(syms->begin(), syms->end());
	}

unsigned int CCL::MemoryAllocation() const
	{
	return padded_sizeof(*this) + padded_sizeof(*syms) + util::pad_size(syms->size() * sizeof(int_list::value_type));
	}

} // namespace zeek::detail
